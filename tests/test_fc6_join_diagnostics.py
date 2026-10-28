import json
import struct
import unittest
from unittest.mock import patch

from fc6_support import MemoryImage

from fc6 import diagnostics


class TestJoinDiagnostics(unittest.TestCase):
    def setUp(self):
        self.base = 0x180000000
        self.memory = MemoryImage()
        self.platform = 0x10000000
        self.platform_data = bytearray(0xE0)
        struct.pack_into("<Q", self.platform_data, 0x10, self.base + 0x5AEF370)
        self.platform_data[0x38] = ord("O")
        struct.pack_into("<I", self.platform_data, 0x3C, 0x214C8F5A)
        struct.pack_into("<I", self.platform_data, 0x64, 0x12BBE504)
        struct.pack_into("<I", self.platform_data, 0x88, 0x6A3C926F)
        self.platform_data[0xD0:0xE0] = b"private-guid-123"
        self.memory.regions[self.platform] = self.platform_data
        self.memory.regions[self.base + diagnostics.PLATFORM_GLOBAL_RVA] = struct.pack(
            "<Q", self.platform
        )
        self.memory.regions[self.platform + 0x3B0] = bytes(0x30)

    def test_reports_stored_result_without_exposing_session_guid(self):
        state = diagnostics.sample_platform(self.memory.read, self.base)

        self.assertTrue(state["session_present"])
        self.assertEqual(state["stored_result"]["code"], "0x214c8f5a")
        self.assertEqual(state["stored_result"]["name"], "INTERNAL_JOIN_HOST_NOT_READY")
        self.assertNotIn("private-guid", json.dumps(state))

    def test_does_not_follow_result_message_pointers(self):
        struct.pack_into("<Q", self.platform_data, 0x48, 0x20000000)
        struct.pack_into("<Q", self.platform_data, 0x58, 0x30000000)
        self.memory.regions[0x20000000] = b"Authorization: secret-token\r\nforged"
        self.memory.regions[0x30000000] = b"session-cookie=private"

        state = diagnostics.sample_platform(self.memory.read, self.base)

        self.assertNotIn("secret-token", json.dumps(state))
        self.assertNotIn("private", json.dumps(state))
        self.assertNotIn((0x20000000, 1), self.memory.reads)
        self.assertNotIn((0x30000000, 1), self.memory.reads)

    def test_rejects_another_platform_interface(self):
        struct.pack_into("<Q", self.platform_data, 0x10, self.base + 0x100)

        with self.assertRaisesRegex(RuntimeError, "platform interface"):
            diagnostics.sample_platform(self.memory.read, self.base)

    def test_reports_uninitialized_platform(self):
        self.memory.regions[self.base + diagnostics.PLATFORM_GLOBAL_RVA] = bytes(8)

        self.assertEqual(
            diagnostics.sample_platform(self.memory.read, self.base),
            {"initialized": False},
        )

    def test_names_the_bookworm_leave_reason(self):
        struct.pack_into("<I", self.platform_data, 0x3C, 0x1E2AEC01)

        result = diagnostics.sample_platform(self.memory.read, self.base)["stored_result"]

        self.assertEqual(result["name"], "INTERNAL_LEAVE_REASON_UNDEFINED")

    def test_preserves_unknown_result_code_without_guessing_a_name(self):
        struct.pack_into("<I", self.platform_data, 0x3C, 0x12345678)

        result = diagnostics.sample_platform(self.memory.read, self.base)["stored_result"]

        self.assertEqual(result["code"], "0x12345678")
        self.assertEqual(result["name"], "unknown")

    def test_array_reader_rejects_oversized_collection(self):
        self.memory.regions[0x40000000] = struct.pack("<QQ", 0x50000000, 257 << 32)

        with self.assertRaisesRegex(RuntimeError, "collection limit"):
            diagnostics.read_pointer_array(self.memory.read, 0x40000000)

    def test_array_reader_rejects_nonempty_null_table(self):
        self.memory.regions[0x40000000] = struct.pack("<QQ", 0, 1 << 32)

        with self.assertRaisesRegex(RuntimeError, "null table"):
            diagnostics.read_pointer_array(self.memory.read, 0x40000000)

    def test_limits_total_service_entries_across_registry_nodes(self):
        self.memory.regions[self.base + diagnostics.SERVICE_CONTAINER_RVA] = struct.pack(
            "<Q", 0x40000000
        )
        container = bytearray(0x38)
        struct.pack_into("<Q", container, 0x30, 0x50000000)
        self.memory.regions[0x40000000] = container
        registry = bytearray(0x20)
        struct.pack_into("<QQ", registry, 0x10, 0x60000000, 2 << 32)
        self.memory.regions[0x50000000] = registry
        self.memory.regions[0x60000000] = struct.pack("<QQ", 0x70000000, 0x70000100)
        node = bytearray(0x28)
        struct.pack_into("<QQ", node, 0x18, 0x80000000, 256 << 32)
        self.memory.regions[0x70000000] = node
        self.memory.regions[0x70000100] = node
        self.memory.regions[0x80000000] = struct.pack("<256Q", *([self.platform] * 256))

        with self.assertRaisesRegex(RuntimeError, "collection limit"):
            diagnostics.sample_services(self.memory.read, self.base)

    def test_reads_mode_capacity_without_exporting_internal_session_id(self):
        self.memory.regions[self.base + diagnostics.MODE_ROOT_RVA] = struct.pack(
            "<Q", 0x40000000
        )
        root = bytearray(0x98)
        struct.pack_into("<Q", root, 0x90, 0x50000000)
        mode = bytearray(0x118)
        struct.pack_into("<Q", mode, 0x110, 0x60000000)
        session = bytearray(0xD0)
        struct.pack_into("<I", session, 0x78, 12345678)
        struct.pack_into("<I", session, 0xA8, 0x6A3C926F)
        session[0xC8:0xCB] = bytes([1, 4, 1])
        self.memory.regions.update({0x40000000: root, 0x50000000: mode, 0x60000000: session})

        state = diagnostics.sample_mode(self.memory.read, self.base)

        self.assertEqual(state, {
            "initialized": True, "mode_id": "0x6a3c926f", "min_team_size": 1,
            "max_team_size": 4, "number_of_teams": 1,
        })

    def test_component_errors_do_not_expose_raw_exception_text(self):
        with patch.object(diagnostics, "sample_platform", side_effect=RuntimeError(
            "secret-token\r\nforged"
        )):
            state = diagnostics.sample_join_state(self.memory.read, self.base)

        self.assertEqual(state["platform"], {"error": "read_failed_or_changed"})
        self.assertNotIn("secret-token", json.dumps(state))

    def test_network_output_excludes_raw_addresses_and_session_ids(self):
        session = {
            "table": "primary", "filled_slots": 1, "reserved_slots": 0,
            "max_slots": 4, "available_slots": 3, "descriptor_max_players": 4,
            "team_record_count": 1, "storm_max_peers": 2, "storm_max_peers_id": 2,
            "consistent": True, "storm_allows_max_slots": False,
            "address": hex(self.platform), "session_id": "private-session-id",
        }
        with patch.object(diagnostics, "sample_sessions", return_value={
            "manager_initialized": True, "sessions": [session],
        }):
            state = diagnostics.sample_network(self.memory.read, self.base)

        self.assertEqual(state["sessions"][0]["max_slots"], 4)
        self.assertEqual(state["sessions"][0]["storm_max_peers"], 2)
        self.assertFalse(state["sessions"][0]["storm_allows_max_slots"])
        self.assertNotIn("address", state["sessions"][0])
        self.assertNotIn("session_id", state["sessions"][0])

    def install_game_players(self, loaded_flags, coop_ready=1):
        """Player service with one player per flag, None meaning no game-mode player yet."""
        service, coop, ready = 0x40000000, 0x41000000, 0x42000000
        table = 0x43000000
        self.memory.regions[self.base + diagnostics.PLAYER_SERVICE_RVA] = struct.pack("<Q", service)
        self.memory.regions[self.base + diagnostics.COOP_SERVICE_RVA] = struct.pack("<Q", coop)
        service_data = bytearray(0x28)
        struct.pack_into("<QQQ", service_data, 0x00, self.base + diagnostics.PLAYER_SERVICE_VTABLE_RVA, 0, 0)
        struct.pack_into("<QQ", service_data, 0x18, table, len(loaded_flags) << 32)
        self.memory.regions[service] = service_data
        coop_data = bytearray(0x1D8)
        struct.pack_into("<Q", coop_data, 0, self.base + diagnostics.COOP_SERVICE_VTABLE_RVA)
        struct.pack_into("<Q", coop_data, 0x1D0, ready)
        struct.pack_into("<I", coop_data, 0xD0, 2)
        self.memory.regions[coop] = coop_data
        self.memory.regions[ready] = bytes(0x40) + bytes([coop_ready])
        players = []
        for index, flag in enumerate(loaded_flags):
            player, game_mode_player, world = 0x50000000 + index * 0x1000000, 0x60000000 + index * 0x1000000, 0x70000000 + index * 0x1000000
            data = bytearray(0x28)
            struct.pack_into("<Q", data, 0, self.base + diagnostics.PLAYER_VTABLE_RVA)
            if flag is not None:
                struct.pack_into("<Q", data, 0x20, game_mode_player)
                mode_data = bytearray(0xB0)
                struct.pack_into("<Q", mode_data, 0xA8, world)
                self.memory.regions[game_mode_player] = mode_data
                self.memory.regions[world] = bytes(0x44) + bytes([flag])
            self.memory.regions[player] = data
            players.append(player)
        self.memory.regions[table] = struct.pack(f"<{len(players)}Q", *players)

    def test_reports_third_player_waiting_for_world(self):
        self.install_game_players([1, 1, 0])

        state = diagnostics.sample_game_players(self.memory.read, self.base)

        self.assertEqual(state["player_count"], 3)
        self.assertEqual([p["world_loaded"] for p in state["players"]], [True, True, False])
        self.assertTrue(state["coop_ready_to_send_mblocks"])
        self.assertEqual(state["coop_mblock_sync_state"], 2)
        self.assertTrue(all(p["player_class_ok"] for p in state["players"]))

    def test_reports_player_without_game_mode_object(self):
        self.install_game_players([1, None], coop_ready=0)

        state = diagnostics.sample_game_players(self.memory.read, self.base)

        self.assertEqual(state["players"][1], {"player_class_ok": True, "game_mode_player": False, "world_loaded": None})
        self.assertFalse(state["coop_ready_to_send_mblocks"])

    def test_game_player_output_has_no_addresses(self):
        self.install_game_players([1, 0])

        text = json.dumps(diagnostics.sample_game_players(self.memory.read, self.base))

        self.assertNotIn("0x", text)

    def test_rejects_unexpected_player_service_object(self):
        self.install_game_players([1])
        self.memory.regions[0x40000000][0:8] = struct.pack("<Q", self.base + 0x100)

        with self.assertRaisesRegex(RuntimeError, "player service"):
            diagnostics.sample_game_players(self.memory.read, self.base)

    def test_reports_uninitialized_player_service(self):
        self.memory.regions[self.base + diagnostics.PLAYER_SERVICE_RVA] = bytes(8)

        self.assertEqual(diagnostics.sample_game_players(self.memory.read, self.base), {"initialized": False})

    def install_peer_mapping(self, peer_ids, players_for):
        """Game session 7 with one member per peer ID, players only for the listed member indexes."""
        manager, table, session = 0x90000000, 0x91000000, 0x92000000
        members_table, service, players_table = 0x93000000, 0x94000000, 0x95000000
        self.memory.regions[self.base + diagnostics.SESSION_MANAGER_RVA] = struct.pack("<Q", manager)
        manager_data = bytearray(0x130)
        struct.pack_into("<QQ", manager_data, 0xC8, table, 1 << 32)
        struct.pack_into("<I", manager_data, 0x128, 7)
        self.memory.regions[manager] = manager_data
        self.memory.regions[table] = struct.pack("<IIQ", 7, 0, session)
        session_data = bytearray(0x4B0)
        struct.pack_into("<Q", session_data, 0, self.base + 0x58E8A08)
        struct.pack_into("<I", session_data, 0x4AC, 7)
        session_data[0x3E0:0x3E3] = bytes([len(peer_ids), 0, 4])
        session_data[0x439:0x43B] = bytes([4, 1])
        struct.pack_into("<QQ", session_data, 0x378, members_table, len(peer_ids) << 32)
        self.memory.regions[session] = session_data
        members = []
        for index, peer_id in enumerate(peer_ids):
            member, left, root = (0xA0000000 + index * 0x100000 + offset for offset in (0, 0x1000, 0x2000))
            # root keyed by session 9 with a smaller left child keyed by session 7
            self.memory.regions[member] = bytes(0x30) + struct.pack("<Q", root)
            self.memory.regions[root] = struct.pack("<QQ", left, 0) + bytes(0x10) + struct.pack("<II", 9, 99)
            self.memory.regions[left] = bytes(0x20) + struct.pack("<II", 7, peer_id)
            members.append(member)
        self.memory.regions[members_table] = struct.pack(f"<{len(members)}Q", *members)
        self.memory.regions[self.base + diagnostics.PLAYER_SERVICE_RVA] = struct.pack("<Q", service)
        service_data = bytearray(0x28)
        struct.pack_into("<Q", service_data, 0, self.base + diagnostics.PLAYER_SERVICE_VTABLE_RVA)
        struct.pack_into("<QQ", service_data, 0x18, players_table, len(players_for) << 32)
        self.memory.regions[service] = service_data
        players = []
        for index in players_for:
            player = 0xB0000000 + index * 0x1000
            self.memory.regions[player] = bytes(0x18) + struct.pack("<Q", members[index])
            players.append(player)
        self.memory.regions[players_table] = struct.pack(f"<{len(players)}Q", *players)

    def test_maps_every_member_to_peer_and_player(self):
        self.install_peer_mapping([0, 1, 2], [0, 1, 2])

        state = diagnostics.sample_peer_mapping(self.memory.read, self.base)

        self.assertEqual(state["members"], [{"peer_id": peer, "has_player": True} for peer in (0, 1, 2)])
        self.assertEqual(state["players_without_member"], 0)

    def test_reports_third_member_without_player(self):
        self.install_peer_mapping([0, 1, 2], [0, 1])

        state = diagnostics.sample_peer_mapping(self.memory.read, self.base)

        self.assertEqual([m["has_player"] for m in state["members"]], [True, True, False])
        self.assertEqual(state["members"][2]["peer_id"], 2)

    def test_reports_missing_peer_entry_for_the_game_session(self):
        self.install_peer_mapping([0, 1], [0, 1])
        left = 0xA0000000 + 0x100000 + 0x1000
        self.memory.regions[left] = bytes(0x20) + struct.pack("<II", 6, 5)

        state = diagnostics.sample_peer_mapping(self.memory.read, self.base)

        self.assertEqual([m["peer_id"] for m in state["members"]], [0, None])

    def test_peer_mapping_output_has_no_addresses(self):
        self.install_peer_mapping([0, 1, 2], [0, 2])

        self.assertNotIn("0x", json.dumps(diagnostics.sample_peer_mapping(self.memory.read, self.base)))

    def test_emits_initial_changed_and_completion_records(self):
        clock = iter([0.0, 0.0, 0.1, 0.2, 0.3, 0.3])
        samples = iter([{"value": 1}, {"value": 1}, {"value": 2}])
        with patch.object(diagnostics.time, "monotonic", side_effect=lambda: next(clock)):
            with patch.object(diagnostics.time, "sleep"):
                events = list(diagnostics.record_changes(lambda: next(samples), 0.3, 0.1))

        self.assertEqual([event["event"] for event in events], ["state", "state", "end"])
        self.assertEqual(events[-1]["samples"], 3)
        self.assertEqual(events[-1]["changes"], 2)


if __name__ == "__main__":
    unittest.main()
