import logging, json
from regipy.registry import RegistryHive

# NTUSER plugins
from regipy.plugins.ntuser.persistence import NTUserPersistencePlugin
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
from regipy.plugins.ntuser.typed_urls import TypedUrlsPlugin
from regipy.plugins.ntuser.classes_installer import NtuserClassesInstallerPlugin
from regipy.plugins.ntuser.installed_programs_ntuser import InstalledProgramsNTUserPlugin
from regipy.plugins.ntuser.shellbags_ntuser import ShellBagNtuserPlugin
from regipy.plugins.ntuser.tsclient import TSClientPlugin
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy.plugins.ntuser.winscp_saved_sessions import WinSCPSavedSessionsPlugin
from regipy.plugins.ntuser.word_wheel_query import WordWheelQueryPlugin
from regipy.plugins.ntuser.wsl import WSLPlugin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_ntuser_plugins():
    hive_path = r"C:\Temp\NTUSER.DAT"  # make sure you exported this hive
    hive = RegistryHive(hive_path)

    plugins = [
        ("Persistence", NTUserPersistencePlugin),
        ("UserAssist", UserAssistPlugin),
        ("TypedURLs", TypedUrlsPlugin),
        ("ClassesInstaller", NtuserClassesInstallerPlugin),
        ("InstalledPrograms", InstalledProgramsNTUserPlugin),
        ("TSClient", TSClientPlugin),
        ("TypedPaths", TypedPathsPlugin),
        ("WinSCP", WinSCPSavedSessionsPlugin),
        ("WordWheelQuery", WordWheelQueryPlugin),
        ("WSL", WSLPlugin),
    ]

    for name, plugin_class in plugins:
        plugin = plugin_class(hive, as_json=True)
        plugin.run()
        logger.info(f"Plugin executed: {name}")

        print(f"\n=== {name} (Text) ===")
        for entry in plugin.entries:
            if not isinstance(entry, dict):
                print(entry)
                continue

            # plugin-specific formatting
            if name == "Persistence":
                print(f"[{entry.get('path')}] {entry.get('value_name')} = {entry.get('value_data')}")
            elif name == "UserAssist":
                print(f"{entry.get('program_name')} | Run {entry.get('run_counter')} times | Last Run: {entry.get('last_execution_time')}")
            elif name == "TypedURLs":
                print(f"{entry.get('url')} | Last Write: {entry.get('last_write_time')}")
            elif name == "TypedPaths":
                print(f"{entry.get('entry')} | Last Write: {entry.get('last_write_time')}")
            else:
                print(json.dumps(entry, indent=2))  # fallback for other plugins

if __name__ == "__main__":
    run_ntuser_plugins()
