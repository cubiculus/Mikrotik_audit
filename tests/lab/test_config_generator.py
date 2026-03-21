"""Tests for lab.config_generator module."""

from src.lab.config_generator import (
    ScenarioGenerator,
    ScenarioRunner,
    ScenarioConfig,
    ScenarioType
)


class TestScenarioGenerator:
    """Tests for ScenarioGenerator."""

    def test_generator_creates_all_scenarios(self):
        """Test that generator creates all scenario types."""
        generator = ScenarioGenerator()
        scenarios = generator.get_all_scenarios()

        assert len(scenarios) == len(ScenarioType)

        scenario_types = [s.scenario_type for s in scenarios]
        for scenario_type in ScenarioType:
            assert scenario_type in scenario_types

    def test_get_scenario_by_type(self):
        """Test getting scenario by ScenarioType."""
        generator = ScenarioGenerator()

        scenario = generator.get_scenario('unreachable_rule')

        assert scenario is not None
        assert scenario.scenario_type == ScenarioType.UNREACHABLE_RULE
        assert scenario.name == "Недостижимое правило"

    def test_get_scenario_by_name(self):
        """Test getting scenario by name."""
        generator = ScenarioGenerator()

        scenario = generator.get_scenario('NAT обходит фаервол')

        assert scenario is not None
        assert scenario.scenario_type == ScenarioType.NAT_BYPASSES_FIREWALL

    def test_get_scenario_unknown_returns_none(self):
        """Test that unknown scenario returns None."""
        generator = ScenarioGenerator()

        scenario = generator.get_scenario('unknown_scenario')

        assert scenario is None

    def test_scenario_has_required_fields(self):
        """Test that each scenario has all required fields."""
        generator = ScenarioGenerator()

        for scenario in generator.get_all_scenarios():
            assert scenario.name, f"Missing name for {scenario.scenario_type}"
            assert scenario.description, f"Missing description for {scenario.scenario_type}"
            assert scenario.setup_commands, f"Missing setup_commands for {scenario.scenario_type}"
            assert scenario.expected_conflicts, f"Missing expected_conflicts for {scenario.scenario_type}"
            assert scenario.cleanup_commands, f"Missing cleanup_commands for {scenario.scenario_type}"

    def test_setup_commands_are_valid_routeros(self):
        """Test that setup commands look like valid RouterOS commands."""
        generator = ScenarioGenerator()

        for scenario in generator.get_all_scenarios():
            for cmd in scenario.setup_commands:
                if cmd.startswith('#') or not cmd.strip():
                    continue  # Skip comments and empty lines
                # RouterOS commands start with /
                assert cmd.startswith('/'), \
                    f"Invalid command in {scenario.name}: {cmd}"

    def test_cleanup_commands_remove_test_items(self):
        """Test that cleanup commands remove test items."""
        generator = ScenarioGenerator()

        for scenario in generator.get_all_scenarios():
            for cmd in scenario.cleanup_commands:
                if cmd.startswith('#') or not cmd.strip():
                    continue
                # Cleanup should use remove or disable
                assert 'remove' in cmd.lower() or 'disable' in cmd.lower(), \
                    f"Cleanup command should remove/disable: {cmd}"

    def test_generate_test_config_combines_scenarios(self):
        """Test generating combined config for multiple scenarios."""
        generator = ScenarioGenerator()

        result = generator.generate_test_config([
            'unreachable_rule',
            'duplicate_rule'
        ])

        assert 'setup_commands' in result
        assert 'expected_conflicts' in result
        assert 'cleanup_commands' in result

        # Should have commands from both scenarios
        setup_text = '\n'.join(result['setup_commands'])
        assert 'Catch-all drop' in setup_text  # From unreachable_rule
        assert 'Allow SSH' in setup_text  # From duplicate_rule

        # Should have conflicts from both
        assert len(result['expected_conflicts']) >= 2

    def test_generate_test_config_unknown_scenario(self):
        """Test generating config with unknown scenario."""
        generator = ScenarioGenerator()

        result = generator.generate_test_config([
            'unreachable_rule',
            'unknown_scenario'
        ])

        # Should still generate for known scenarios
        assert 'setup_commands' in result
        setup_text = '\n'.join(result['setup_commands'])
        assert 'Catch-all drop' in setup_text

    def test_validate_scenario_returns_issues(self):
        """Test scenario validation."""
        generator = ScenarioGenerator()

        is_valid, issues = generator.validate_scenario('unreachable_rule')

        assert is_valid is True
        assert len(issues) > 0
        # Should have warning about test routers
        assert any('test' in issue.lower() for issue in issues)

    def test_validate_unknown_scenario_returns_false(self):
        """Test validating unknown scenario."""
        generator = ScenarioGenerator()

        is_valid, issues = generator.validate_scenario('unknown')

        assert is_valid is False
        assert any('Unknown' in issue for issue in issues)

    def test_get_scenario_names_returns_list(self):
        """Test getting all scenario names."""
        generator = ScenarioGenerator()

        names = generator.get_scenario_names()

        assert isinstance(names, list)
        assert len(names) == len(ScenarioType)
        assert 'Недостижимое правило' in names


class TestScenarioConfig:
    """Tests for ScenarioConfig dataclass."""

    def test_create_scenario_config(self):
        """Test creating ScenarioConfig."""
        config = ScenarioConfig(
            name="Test Scenario",
            scenario_type=ScenarioType.UNREACHABLE_RULE,
            description="Test description",
            setup_commands=["/command1", "/command2"],
            expected_conflicts=["CONFLICT_TYPE"],
            cleanup_commands=["/remove"],
            prerequisites=["Prereq 1"],
            warnings=["Warning 1"]
        )

        assert config.name == "Test Scenario"
        assert len(config.setup_commands) == 2
        assert len(config.cleanup_commands) == 1
        assert len(config.warnings) == 1

    def test_create_scenario_config_defaults(self):
        """Test creating ScenarioConfig with defaults."""
        config = ScenarioConfig(
            name="Test",
            scenario_type=ScenarioType.DUPLICATE_RULE,
            description="Test"
        )

        assert config.setup_commands == []
        assert config.expected_conflicts == []
        assert config.cleanup_commands == []
        assert config.prerequisites == []
        assert config.warnings == []


class TestScenarioType:
    """Tests for ScenarioType enum."""

    def test_all_conflict_types_have_scenario(self):
        """Test that all ConflictType have corresponding ScenarioType."""
        # Import ConflictType for comparison
        from src.conflict_analyzer import ConflictType

        # Map of ConflictType to ScenarioType
        type_mapping = {
            ConflictType.UNREACHABLE_RULE: ScenarioType.UNREACHABLE_RULE,
            ConflictType.NAT_BYPASSES_FIREWALL: ScenarioType.NAT_BYPASSES_FIREWALL,
            ConflictType.ORPHAN_ROUTING_MARK: ScenarioType.ORPHAN_ROUTING_MARK,
            ConflictType.INTERFACE_NOT_IN_LIST: ScenarioType.INTERFACE_NOT_IN_LIST,
            ConflictType.ADDRESS_LIST_CONFLICT: ScenarioType.ADDRESS_LIST_CONFLICT,
            ConflictType.FORWARD_WITHOUT_FASTTRACK: ScenarioType.FORWARD_WITHOUT_FASTTRACK,
            ConflictType.SHADOWED_RULE: ScenarioType.SHADOWED_RULE,
            ConflictType.DUPLICATE_RULE: ScenarioType.DUPLICATE_RULE,
        }

        # All ConflictTypes should have mapping
        for conflict_type in ConflictType:
            assert conflict_type in type_mapping, \
                f"Missing ScenarioType for {conflict_type}"


class TestScenarioRunner:
    """Tests for ScenarioRunner."""

    def test_runner_initialization(self):
        """Test ScenarioRunner initialization."""
        # Mock SSH handler
        class MockSSH:
            def execute_command(self, cmd):
                return {'exit_status': 0, 'stdout': '', 'stderr': ''}

        runner = ScenarioRunner(MockSSH())

        assert runner.generator is not None
        assert runner.applied_scenarios == []

    def test_apply_unknown_scenario_returns_false(self):
        """Test applying unknown scenario."""
        class MockSSH:
            def execute_command(self, cmd):
                return {'exit_status': 0}

        runner = ScenarioRunner(MockSSH())

        success, output = runner.apply_scenario('unknown')

        assert success is False
        assert any('Unknown' in msg for msg in output)

    def test_cleanup_clears_applied_scenarios(self):
        """Test that cleanup clears applied scenarios list."""
        class MockSSH:
            def execute_command(self, cmd):
                return {'exit_status': 0, 'stdout': '', 'stderr': ''}

        runner = ScenarioRunner(MockSSH())

        # Manually add to applied list (simulating applied scenario)
        runner.applied_scenarios.append('test_scenario')
        assert len(runner.applied_scenarios) > 0

        # Cleanup should clear the list
        success, output = runner.cleanup()

        assert success is True
        assert runner.applied_scenarios == []
