# Upgrade log

Branch `upgrade/real-antivirus`.

## Scope of this pass

The written plan for this branch (`the-nex-claude-code-prompt.md`) was not on the machine this
work was done on, and no copy could be found. Nothing here is guessed from its title. This pass
covers the work that was described outside that file: apply the plain-language patch, build, run
and test the Windows version for real, and write down and fix every bug found. The plan's own
items and their priority order are still open.

## Where it was run

Windows 11 Home 10.0.26300, 64-bit, ordinary (not administrator) account, Rust 1.100.0 (MSVC).
Before any change: 267 Rust tests passed, 0 failed, 4 ignored.

## Bugs found and fixed

| # | What went wrong on Windows | How it was seen | Fix | Test |
|---|---|---|---|---|
| 1 | A restored file went straight back into quarantine (three times in a row) | log of a real install | an estimate only reports a file a person put back, matched by place and SHA-256; a known-malware match still quarantines | `a_restored_file_stays_where_it_was_put`, live run |
| 2 | Full Scan never worked: the app did not hand scans to the service | reading the code, then a failing test | the service lets local users add request files; the app uses it | `a_requested_full_scan_runs_reports_and_never_moves_files`, real app |
| 3 | With the tray running, AI detections and ransomware suspects raised no notification at all | reading the code, then a failing test | every event above Low severity alerts | `every_detection_is_an_alert_and_a_record_is_not` |
| 4 | Scans and live protection opened online-only OneDrive files, which downloads them | reading the code, then a real cloud placeholder | they are left alone until their content arrives | `only_content_windows_would_download_is_left_alone`, real placeholder |
| 5 | Every PowerShell command run by Claude Code was terminated | command line of a running process | one weak sign alone is recorded quietly, two (or one with a fetch or decode) are stopped | `one_weak_sign_alone_is_recorded_and_never_stopped` |
| 6 | A laptop maker's updater was flagged for running a script in a hidden window | log of a real install | same as 5 | same as 5 |
| 7 | A Minecraft modpack was quarantined as a zip bomb, only because it holds jars inside jars | log of a real install | jars may nest two levels deeper; size and ratio are still checked all the way down | `jars_inside_jars_are_how_programs_are_packed` |
| 8 | The app would give up on a service scan after 180 s in all (one real quick scan took 1,073 s) | log of a real install | 180 s without progress | `a_long_scan_is_waited_for_while_it_moves` |
| 9 | Folders under `C:\Users` that could not be read were missing from the report, so a scan could read as clean | reading the code, then a failing test | the drive is ignored when comparing | `a_locked_folder_of_a_person_is_reported_by_a_full_scan` |
| 10 | Paths were shown as `\\?\C:\...` | log of a real install | plain paths are recorded | `the_recorded_place_is_written_the_way_people_read_it` |
| 11 | A backtick (`` i`ex ``) hid a PowerShell pattern | writing the test for 5 | backticks are ignored like quotes and carets | `a_weak_sign_with_another_or_with_something_fetched_or_decoded_is_stopped` |
| 12 | The scheduled scan's report was not recognised as the engine's own file | reading the code, then a failing test | added to the list | `every_report_the_engine_writes_is_its_own_output` |
| 13 | The build needs Rust 1.96, which nothing said (25 dependency errors on 1.89) | the first build | `rust-version` in `Cargo.toml` | - |
| 14 | Another file of the same size and modified time could take the place of a judged file, and an always-allowed decision then covered it (Windows CI failed on this already) | CI of the main branch, then a failing test | the stamp on Windows is the file's volume, index and change time | `a_same_size_file_with_a_forged_time_is_still_another_file` |
| 15 | Install in the app registered the service but never started it ("installed but not responding", Windows exit code 1077) | this PC | install starts it | live, after approval |
| 16 | Install in the app made the SYSTEM service run the program from wherever the app was, such as a build folder any program of the user's could change | this PC | install copies the program into the protected data folder and registers that copy | `the_service_runs_a_copy_in_the_protected_folder` |

Decisions worth knowing:

- **4:** only `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` counts. `attrib +O` lets any program mark its
  own file offline, so skipping on that would be a way to hide from every scan. Checked on this
  PC: a program can set OFFLINE and cannot set RECALL_ON_DATA_ACCESS.
- **5 and 6 make the guard less strict on purpose.** A lone hidden window, `-ep bypass` or
  `Invoke-Expression` no longer ends the process. The startup list still treats them as suspicious.
- **1:** remembered through the event log, so until that rotates (50 MB).

## Added: always open as administrator (Windows)

Settings, "Running in the background": a switch that makes the app start itself again through the
Windows approval prompt each time it opens, so Restore, Delete and Always allow do not ask again
while it is open. Declining the prompt opens it as usual; an elevated copy never starts another.
The choice is an empty file, `%APPDATA%\TheNex\open-as-administrator`. Dragging a file onto
the window does not work while it runs as administrator (Windows blocks it). Checked in the real
app: the switch saves and clears the choice. Not checked: the restart itself, which needs a
person to approve the prompt.

## Merged with main

`main` moved on while this branch was made (never-scan list, a new app layout, plain words of
its own, fixes from two reviews). In the merge, the app's pages, their tests and the README
are main's: its own plain-language redesign replaces the patch's, and the patch's copy of the
old README (`docs/TECHNICAL.md`) is gone. Main had fixed the scan wait the same way (bug 8); its
version is kept. Its restore message now says what is true after bug 1.

## Independent review

One reviewer read the diff without being told the conclusions. Acted on:

- **The relaxed command-line rules went too far.** A hidden window running a script from Temp,
  Downloads, AppData, Desktop or Public, or `iex` on a file's content, is stopped again.
- **A program can make its own cloud placeholders** (this pass did so as a standard user to test
  bug 4). Scans now skip only placeholder files, never a folder, so a folder of them cannot hide
  what is in it.
- **`was_restored` parsed the whole log on every detection.** It now parses only lines that
  mention a restore, and also reads the rotated log.
- **Waiting for a scan was kept alive by any scan**, including the scheduled one. It now waits
  only while the kind of scan asked for is running, and its test has a real margin.
- **Paths of 248 characters or more** keep their `\\?\` form.

Left as is, with the reason:

- Any local user can keep a request file open, so others' requests are ignored until the service
  restarts. This was already true on macOS, where scans already went through the request folder.
  The design note at the top of `scan_jobs.rs` already says requests have no per-user checks.
- `cargo clippy -D warnings` fails on one `chunks_exact` in `platform/windows.rs`. That code was
  already there, and CI does not run clippy.

## Measured on this PC

| What | Result |
|---|---|
| Rust tests | 280 passed, 0 failed, 4 ignored |
| Node tests | 9 of 9 files |
| Live checks (`scripts/verify_thenex.py`) | 13 of 13 run; check 7 (process kill) skipped, see below |
| AegisMesh checks | 22 of 22 |
| AI on the committed EMBER2024 sample | 59.2% of 1,020 malware caught, 3.0% of 1,020 clean flagged |
| AI on real Windows programs | 0 of 400 OS programs flagged |
| Rust and Python features | 779 files compared, 0 differ |
| Quick scan speed | 17 ms per signed program, 13 ms per zip, 0.5 ms per other file |
| Real cloud placeholder | skipped, not downloaded |

The 1,073 s scan was not reproduced. One of its folders was in OneDrive and nothing was skipped,
which fits bug 4, but that is not proven.

## Not done or not checked

- The plan in the missing file.
- **Live check 7** was not run on this PC: it would have ended script hosts that belonged to other
  running programs. CI runs it.
- **The installed service** (running as SYSTEM, the installer, the administrator prompts) was not
  run on this PC. CI installs it on a throwaway machine and now checks the request folder too.
- **The dashboard pages** were not seen: the app shows a sign-in page first. Its window, sign-in
  page and commands were exercised.
- No known-malware list ships yet, so that check still catches nothing.
- Binaries are still installed under ProgramData (see the note in `platform/windows.rs`).
- A folder swapped for a junction between a check and a move (see `quarantine.rs`) is still open.
- macOS was not run here; CI builds and tests it.
