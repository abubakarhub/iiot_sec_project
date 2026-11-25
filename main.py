"""
main.py - Single entry point for secureTeam_SecureIoT-Sim.

    python main.py --mode insecure     run the baseline Smart Building
    python main.py --mode secure       run the secured system (+ Module 2/3/4 demos)
    python main.py --compare           attack both modes with the same code and compare
    python main.py --mode secure --live    LIVE simulation in the browser (see below)

Extra options:
    --live          start straight into the live simulation: devices keep sending,
                    control panel on http://127.0.0.1:5050 (launch attacks with a click),
                    cloud dashboard on http://127.0.0.1:5000/dashboard. Ctrl+C stops it.
    --serve         do the full console run first, then continue live as with --live
    --rounds N      how many readings each device sends (default 5)
    --no-attacks    skip the Module 1 attacks (normal simulation only)
    --verbose       show every message (debug logging)

Everything runs on 127.0.0.1 only.
"""

import argparse
import logging
import os
import sys
import time

import compare
import config
from core.control_panel import create_control_panel
from core.http_util import http_json
from core.live import LiveSimulation
from core.simulation import SmartBuilding
from core.webserver import ServerThread
from module1_attacks import attack_runner, trees
from module2_crypto import benchmark
from module2_crypto import demo as crypto_demo
from module3_access import demo as access_demo
from module4_cloud import demo as cloud_demo


def parse_args():
    """Read the command-line options."""
    parser = argparse.ArgumentParser(description="SecureIoT-Sim: simulated Smart Building security")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--mode", choices=["insecure", "secure"], help="which system to run")
    group.add_argument("--compare", action="store_true",
                       help="run all attacks on both modes and compare")
    parser.add_argument("--rounds", type=int, default=config.SIM_ROUNDS,
                        help="readings per device (default %(default)s)")
    parser.add_argument("--serve", action="store_true",
                        help="after the console run, keep the simulation running live until Ctrl+C")
    parser.add_argument("--live", action="store_true",
                        help="go straight into the live simulation (control panel + dashboard)")
    parser.add_argument("--no-attacks", action="store_true",
                        help="only run the normal simulation, skip Module 1 attacks")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    return parser.parse_args()


def setup_logging(verbose):
    """Print log lines as 'HH:MM:SS [component] message'."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, stream=sys.stdout,
                        format="%(asctime)s [%(name)s] %(message)s", datefmt="%H:%M:%S")


def print_header(text):
    """Print a section title so the console output is easy to follow."""
    print("\n" + "=" * 70 + f"\n {text}\n" + "=" * 70)


def summarise_reading(payload):
    """Turn a reading dictionary into a short human-readable string."""
    skip = {"device_id", "device_type", "ts"}
    return ", ".join(f"{key}={value}" for key, value in payload.items() if key not in skip)


def show_latest_readings(building):
    """Fetch the newest reading of each device through the cloud REST API and print it."""
    status, rows = http_json("GET", f"{building.api_url}/api/readings?limit=200")
    if status != 200:
        print(f"  could not read API (status {status}): {rows}")
        return
    latest = {}
    for row in rows:                              # rows are newest first
        latest.setdefault(row["device_id"], row)
    print(f"  {'device':<11} {'topic':<38} reading")
    for device_id in sorted(latest):
        row = latest[device_id]
        print(f"  {device_id:<11} {row['topic']:<38} {summarise_reading(row['payload'])}")


def demo_door_command(building):
    """Log in as the operator through the API and unlock/lock door lock-01."""
    user = next(u for u in config.SEED_USERS if u[0] == "operator1")
    status, body = http_json("POST", f"{building.api_url}/api/login",
                             {"username": user[0], "password": user[1]})
    shown = str(body.get("token"))
    shown = shown if len(shown) <= 30 else shown[:30] + "..."
    print(f"  login as operator1      -> HTTP {status}, token={shown}")

    lock = building.device("lock-01")
    for command in ("unlock", "lock"):
        status, _ = http_json("POST", f"{building.api_url}/api/command",
                              {"device_id": "lock-01", "command": command,
                               "issued_by": "operator1"}, token=body.get("token"))
        time.sleep(0.3)                           # give the command time to travel
        print(f"  command {command:<7} lock-01 -> HTTP {status}, lock-01 is now {lock.state.upper()}")


def show_baseline_weaknesses(building):
    """Point out insecure things that can already be seen in the running baseline."""
    stored = building.db.get_user("operator1")["password"]
    real = next(u[1] for u in config.SEED_USERS if u[0] == "operator1")
    print(f"  passwords stored in plaintext in the DB : {'YES' if stored == real else 'no'}")
    status, _ = http_json("POST", f"{building.api_url}/api/command",
                          {"device_id": "lock-02", "command": "lock"})
    print(f"  /api/command works with NO token        : {'YES' if status == 200 else 'no'} "
          f"(HTTP {status})")
    sample = building.db.get_readings(limit=1)[0]["payload"]
    print(f"  readings travel as readable JSON        : YES, e.g. {summarise_reading(sample)}")


def run_mode(mode, rounds, serve, run_attacks=True):
    """Start the building in one mode, generate traffic, attack it and show what happened."""
    print_header(f"SecureIoT-Sim  |  mode = {mode.upper()}")
    if mode == "insecure":
        paths = trees.draw_all(config.RESULTS_DIR)
        print("  attack/fault trees saved: " + ", ".join(os.path.basename(p) for p in paths))
    else:
        print("  running cipher benchmark (AES-256-GCM vs ChaCha20-Poly1305)...")
        benchmark.print_summary(benchmark.main(config.RESULTS_DIR))
        print("  saved: cipher_benchmark.csv, cipher_benchmark.png")
    with SmartBuilding(mode) as building:
        online = building.start()
        print(f"  broker  : {config.HOST}:{config.BROKER_PORT}")
        print(f"  cloud   : {building.api_url}")
        print(f"  devices : {online}/{len(building.devices)} online")

        print_header(f"Normal operation: {rounds} rounds of readings")
        stored = building.run_rounds(rounds)
        print(f"  devices sent {rounds * len(building.devices)} readings, cloud stored {stored}")
        show_latest_readings(building)

        print_header("Door lock control through the cloud API")
        demo_door_command(building)

        if mode == "insecure":
            print_header("Baseline weaknesses visible right now")
            show_baseline_weaknesses(building)
        else:
            print_header("Module 2: cryptography and key management")
            crypto_demo.run(building)
            print_header("Module 3: access control and privacy")
            access_demo.run(building)
            print_header("Module 4: cloud security")
            cloud_demo.run(building)

        if run_attacks:
            print_header(f"Module 1: running every attack against {mode.upper()} mode")
            results = attack_runner.run_all(building)
            csv_name = "before.csv" if mode == "insecure" else "after.csv"
            csv_path = os.path.join(config.RESULTS_DIR, csv_name)
            attack_runner.write_csv(results, csv_path)
            print_header(f"Attack results ({mode.upper()})  ->  results/{csv_name}")
            attack_runner.print_table(results)
            if mode == "secure":
                print_header("Module 4: audit log and alerts raised during the attacks")
                cloud_demo.print_alert_summary(building)

        if serve:
            run_live(building)
    print("\nDone.")


def run_live(building):
    """Keep the building running: live traffic, control panel and dashboard until Ctrl+C."""
    # The panel URL is given to the cloud dashboard so it can show a button to the panel.
    live = LiveSimulation(building, panel_url=f"http://{config.HOST}:{config.PANEL_PORT}/")
    panel = ServerThread(create_control_panel(live), config.HOST, config.PANEL_PORT,
                         name="control panel")
    live.start()
    panel.start()
    print_header(f"LIVE simulation ({building.mode.upper()} mode) - Ctrl+C to stop")
    print(f"  Control panel  : http://{config.HOST}:{config.PANEL_PORT}   "
          "(live devices, gateway traffic, launch attacks)")
    print(f"  Cloud dashboard: {building.api_url}/dashboard")
    if building.mode == "secure":
        print("  Dashboard sign-in: a seed account from config.py - admin sees alerts, "
              "operator1 can open doors, viewer1 can only read (RBAC).")
    else:
        print("  Dashboard: no sign-in at all (insecure baseline).")
    print("  Switch between INSECURE (before) and SECURE (after) with the switch on the panel.")
    print(f"  Devices publish a reading every {live.interval:.0f} s. "
          "Stop with Ctrl+C or the 'Stop simulation' button.", flush=True)
    try:
        while not live.stop_requested.wait(0.5):      # until Ctrl+C or the Stop button
            pass
    except KeyboardInterrupt:
        pass
    finally:
        time.sleep(0.3)                               # let the Stop button's reply reach the page
        live.stop()
        panel.stop()
        live.building.stop()          # may be a different building after a mode switch


def run_live_only(mode):
    """--live: start the building and go straight into the live simulation."""
    print_header(f"SecureIoT-Sim  |  mode = {mode.upper()}  |  live")
    with SmartBuilding(mode) as building:
        online = building.start()
        print(f"  {online}/{len(building.devices)} devices online, sending first readings...")
        building.run_rounds(1)
        run_live(building)
    print("\nDone.")


def run_comparison(rounds):
    """Attack both modes with the same code and show the before/after comparison."""
    print_header("SecureIoT-Sim  |  --compare: every attack against BOTH modes")
    start = time.time()
    rows = compare.run_compare(rounds)
    print_header("Before / after comparison")
    compare.print_table(rows)
    blocked = sum(1 for r in rows if r["after_outcome"] == "BLOCKED")
    limited = sum(1 for r in rows if r["after_outcome"] == "PARTIAL")
    errors = sum(1 for r in rows if "ERROR" in (r["before_outcome"], r["after_outcome"]))
    print(f"\n  {len(rows)} attacks: {blocked} blocked, {limited} limited, "
          f"{sum(1 for r in rows if r['after_outcome'] == 'SUCCEEDED')} still succeed in secure mode")
    if errors:
        print(f"  WARNING: {errors} attack(s) could not run (ERROR) - see the log above")
    print("  saved: results/before.csv, after.csv, comparison.csv, comparison.md, before_after.png")
    print("         (+ attack_tree.png, fault_tree.png, cipher_benchmark.*, privacy_before_after.png,"
          " analytics_export.csv)")
    print(f"  total time: {time.time() - start:.0f} s")


def main():
    """Program entry point."""
    args = parse_args()
    setup_logging(args.verbose)
    if args.compare:
        run_comparison(args.rounds)
        return 0
    try:
        if args.live:
            run_live_only(args.mode)
        else:
            run_mode(args.mode, args.rounds, args.serve, run_attacks=not args.no_attacks)
    except NotImplementedError as err:
        print(f"Not available yet: {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
