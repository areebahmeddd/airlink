# Testing

The protocol core is plain C with no ESP-IDF dependency, so most of the firmware is tested on the host, where it builds exactly as it does for the device. What only hardware can show (radio range, timing, power, phones' own behavior) is the runbook below.

## On the Host

Each runs in the tools image (`scripts/docker.sh '<command>'`); `scripts/check.sh`, run from the host, runs all of them but coverage, as CI does.

| Check                      | Command                                                                                                | What it covers                                                                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unit tests and simulations | `cmake -S test/host -B build-host -G Ninja && cmake --build build-host && ctest --test-dir build-host` | Every rule in [PROTOCOL.md](PROTOCOL.md), the LoRa trunk between simulated radios, multi-node meshes of simulated phones and nodes, under ASan and UBSan             |
| Spec vectors               | `python3 tools/vectors/gen_spec_vectors.py test/vectors/spec-vectors.json`                             | Packets and DEFLATE streams written from Airhop's PROTOCOLS.md and RFC 1951 alone, sharing no code with the firmware; bitchat-ios's recorded vectors sit beside them |
| Fuzzing                    | `scripts/fuzz-smoke.sh` (`FUZZ_SECONDS=3600` before a release)                                         | libFuzzer over the frame codec, every payload parser, Noise reads, a GCS round trip, the node's receive path and the trunk                                           |
| Static analysis            | `scripts/static-analysis.sh`                                                                           | clang-tidy's analyzer, bug-prone and CERT C checks over the core; cppcheck over every component and `main/`                                                          |
| Coverage                   | `scripts/coverage.sh`                                                                                  | Line and branch coverage of the core by the host tests                                                                                                               |
| Size gate                  | `scripts/size-gate.sh <board>` after a dev build                                                       | Image and static RAM against `test/size-baseline.json`                                                                                                               |

CI adds CodeQL over the host-built C, the Python tools and the workflows, and OpenSSF Scorecard over the repository's practices.

## On a Device

The smoke suite and the LoRa pairing test run from pytest-embedded given the ports (`test/device/conftest.py`):

```bash
pytest test/device -m "not lora" --embedded-services esp,idf --erase-all y \
    --app-path build/heltec_v4-dev --port /dev/ttyUSB0
AH_REGION=eu pytest test/device -m lora --embedded-services esp,idf --count 2 \
    --app-path "build/heltec_v4-dev|build/heltec_v4-dev" --port "/dev/ttyUSB0|/dev/ttyUSB1"
```

## Hardware Runbook

Scenarios S1 to S17 confirm the protocol with real boards and real phones, each with its steps, what to record and its pass bar. A pass bar is a target to confirm by measurement: when one proves unrealistic, record the measured value and why, and never quietly relax it.

### Equipment

- Three tier-1 boards of one kind (Heltec V4, V4-R8 or V3; read the V4's chip marking, ESP32-S3R2 or ESP32-S3R8, and build the matching image), with antennas for the region's band: S4 uses two, and S13's LoRa tests three.
- Two tier-2 boards (ESP32-C6-DevKitC-1 or XIAO ESP32-C6).
- Four phones: Airhop on iOS, Airhop on Android, bitchat-ios, bitchat-android. Record each app's version.
- A computer with ESP-IDF v6.1 (or the tools image), a serial terminal at 115200 baud, and USB cables.
- For S16: a power profiler (a Nordic PPK2 or similar) in series with the battery.
- For S14 and S8 (optional, recommended): a Bluetooth LE sniffer (an nRF52840 dongle with nRF Sniffer for Bluetooth LE in Wireshark) to count packets on the air.

### Keeping Phones Apart

Most scenarios need the node to be the only path between two phones. Bluetooth reaches 30 to 100 m in the open and through a wall or two indoors, so:

- Put the phones in two rooms with at least two walls, or two floors, between them, or 150 m apart outdoors, with the node where both reach it.
- **Check isolation before every session:** with the node powered off, both phones open on the same channel for two minutes. Neither may list the other. If one does, move them further apart.
- Turn off Wi-Fi and mobile data on the phones (Airhop and bitchat can reach each other over the internet through Nostr), and Wi-Fi Aware and LAN in Airhop's settings.

### Preparing the Boards

```bash
scripts/build.sh heltec_v4 dev flash monitor        # one board; repeat for each
```

At each board's console:

```text
region eu                  # the region you are in: us, eu, in, anz or sea
nickname relay-west        # optional; up to 20 ASCII letters, digits, '-', '_', '.'
owner <key> <fingerprint>  # for S14 only: as tools/ota_manifest.py keygen prints it
reboot
status
```

Record each board's `status`: firmware version, board, peer ID, region. Keep the console open with logs saved to a file for every scenario; `status` before and after each one.

### Scenarios

#### S1. Airhop iOS, a Node, Airhop Android, Phones Out of Each Other's Range

1. The iOS phone in room A, the Android phone in room B, the node between them in reach of both.
2. Open both apps. Time from opening to each seeing the other in the peer list.
3. On each phone the node appears as equipment (a radio tower icon, with no Message or Send ecash action).
4. Send a public message each way; time from send to display (a stopwatch, or screen recordings of both phones).
5. Start a DM from iOS; time to the first message delivered; check the delivered and read receipts return.

Pass: mutual discovery within one announce interval plus 5 s (about 35 s); the node shown as equipment; public message under 2 s; DM handshake and first message under 5 s; receipts return.

#### S2 and S3. Airhop with bitchat-ios, and with bitchat-android, Through the Node

As S1 with one Airhop phone and one bitchat phone. Add: send a location-channel message (Airhop's `0x51`) from Airhop; bitchat cannot show it, but a second Airhop phone placed with the bitchat phone must receive it unchanged.

Pass: public messages and DMs both ways; `0x51` relayed through unchanged.

#### S4. Two Nodes over LoRa Only, a Phone at Each

1. Two tier-1 boards, provisioned to the same region, far enough apart that Bluetooth cannot bridge them (two buildings, or 500 m and more outdoors). A phone at each node, out of each other's Bluetooth range.
2. Watch both consoles for `neighbor ... up` (the trunk link). A board powered on for the first time logs `duty ledger taken as spent`: its first beacon waits up to a minute and its data about seven ([LORA.md](LORA.md), "Across resets"); one powered on again logs `restored from flash`, and one restarted with `reboot` logs `carried over the reset`, and those wait only for what they spent in the hour before. Start step 3 once both trunks have been up seven minutes.
3. Time from opening the far phone to it seeing the near phone's announce.
4. Send a public message each way; a DM each way (handshake included).
5. Send a voice note, a photo and a file from one phone; start a live voice call.
6. `status` on both nodes just before and just after step 5: `trunk refused` must grow by step 5's packets and fragments (it also grows with every announce the presence throttle holds back, about one every 15 s, so compare it against a quiet minute). The frames each node sent over LoRa (`frames sent` in `status`) must not grow by more than steps 3 and 4 explain.

Pass: announce across within 60 s; public message under 10 s; DM handshake and message under 30 s; zero media, file or sync packets on the trunk; `lora transfers` shows no bad frames and no more than a few from unknown nodes, which only the first seconds after a boot account for. Record the distance, terrain, RSSI and SNR (the console logs both for each frame received), and the airtime used.

#### S5. Mail for an Absent Phone, Node Rebooted, Phone Arrives

1. Phone A next to the node; phone B away (out of range, or Bluetooth off).
2. A sends B a DM. With B unreachable, Airhop leaves it as courier mail with a carrier in reach, here the node.
3. `status`: `mail stored` grows. Power-cycle the node.
4. Bring B within range of the node (not of A). B receives the DM; `mail delivered` grows; the mail is retired (`status` again after a minute).
5. Repeat with B away for over 25 h: the envelope must be gone and not delivered.

Pass: the envelope survives the reboot, is handed over, retired, and opens; one past 25 h is refused. A board without PSRAM holds envelopes up to about 4 KiB ([MEMORY.md](MEMORY.md)): use a text DM.

#### S6. Catch-Up: Posts Made While a Phone Was Away

1. Phones A and B with the node; B leaves range.
2. A posts public messages, a board post, and a location-channel message.
3. B returns. Time until each appears on B.

Pass: messages within one 15 s round; board posts within 60 s; location channels (sync bit 24) too.

#### S7. Live Voice Through One Node

A push-to-talk call between two phones that reach each other only through the node, for five minutes. Measure the added latency (a click track: tap the microphone, record both phones' audio, compare the click's arrival) with and without the node in the path (phones together, then apart). `status` and the heap before and after.

Pass: under 50 ms median added per hop; no stale frames played; heap and CPU stable.

#### S8. Live Video Through One Node at Peak Rate

A video call at the High preset for five minutes through the node. A sniffer capture of the node's two links.

Pass: plays end to end; zero duplicate forwards across the 150 s window (each frame forwarded once on each link). On a board without PSRAM, record duplicates past 21 s rather than failing on them ([MEMORY.md](MEMORY.md)).

#### S9. A 1 MiB File Through One Node

Send a 1 MiB file between two phones through the node. Record the time and `status` before and after.

Pass: completes; fragments forwarded individually (the node's `relayed` grows by about the fragment count, and no reassembled packet appears in the capture); message dedup unaffected (a message sent during the transfer arrives once).

#### S10. A Ring of Three Nodes with Phones

Three nodes in a triangle, each in Bluetooth reach of the other two, a phone at each. Send ten public messages from one phone.

Pass: each packet forwarded once per node (`relayed` on each node grows by ten, give or take announces; a capture shows no repeats).

#### S11. More Phones Than Connection Slots

Seven or more phones around one node. The node holds six connections and dials at most two of them to other nodes; nodes that dial it count among the six, so beside several other nodes phones may find fewer than four. Record the connections each takes.

Pass: the behavior when full is as documented (a phone past the free connections is not taken, and reaches the mesh through another phone); node-to-node links are kept; phones still reach each other through other phones.

#### S12. Cold Boot with No Time Source, Then a Hostile Clock Claim

1. Erase the node (`--erase-all`), boot it with no phone and no other node near: its console shows the clock unsynced, and a sniffer or a phone shows no announce from it.
2. Bring one phone: the clock goes tentative, then synced after its announces agree for 30 s; the node's announce appears. `status` shows the clock not yet confirmed.
3. Bring a second phone with the right time: the clock is confirmed.
4. Erase a second node and boot it with no phone in reach but in range of the first, synced node (Bluetooth or LoRa): it takes its time from that node, announces, and its link binds; its clock stays unconfirmed.
5. Set a phone's clock 10 minutes off and bring it alone to a third fresh node holding mail: the node may run on that time, but it never confirms it, expires no mail and saves no clock floor; when two phones with the right time arrive, the clock moves to theirs.
6. Reboot that node and bring the skewed phone back alone, now an hour ahead: the node syncs on it. Bring one phone with the right time: its link binds and it relays. Take the skewed phone away: 10 minutes later the node runs on the honest phone's time, unconfirmed.

Pass: nothing time-checked originated until synced; the first announce accepted by phones; a node with only other nodes in reach syncs and relays; a lone skewed phone deletes no mail, leaves no floor behind, and never shuts out a phone with the right time.

#### S13. Chaos

- Power cut during a mail write (cut power the moment `mail stored` changes) and during an OTA (cut it mid transfer, and again just after the reboot into the new image): the store reads back whole; the OTA rolls back.
- Disconnect storms: toggle Bluetooth on a phone twenty times in a minute.
- A deposit flood: a test phone depositing 4 KiB envelopes as fast as its link takes them for ten minutes. Record the rate reached (`mail stored` against time): it sizes the flash wear an unbounded mailbox would see ([MEMORY.md](MEMORY.md)). Once the hour's `AH_MAIL_FLASH_KIB_PER_HOUR` is spent, `mail refused` grows and `mail stored` stops until the hour is up, while relaying carries on.
- A signature and inflate flood: a test phone sending forged file transfers in another phone's name (signatures broken, each payload its own) as fast as its link takes them for two minutes, then compressed messages that each inflate to 32 KiB. Meanwhile a second phone's leave and file transfer still cross, and a third phone that connects binds within a few seconds. Record `short of: verify` and `inflate` and `longest mesh pass` with the board. Time one Ed25519 check on each chip too (`esp_timer_get_time` around `ah_ed25519_verify` in a scratch build): the defaults of `AH_VERIFY_PER_SECOND` assume about 30 ms on the S3 and 19 ms on the C6 at 160 MHz, from other chips' published figures, and the budget should come to about a quarter of a second of checks on the board's own figure.
- One packet to several neighbors: three tier-1 boards in mutual range, a phone at one posting a public message every minute for ten minutes. On the posting node each message is one transfer to both neighbors: its `frames sent` in `status` grows by a message's pieces once, not once per neighbor, and `delivered` by two; both neighbors deliver every message, and a capture shows their answers one after the other, never overlapping.
- Forgery and rejoin on LoRa: a test tool on a third board sending frames under a neighbor's ID tagged under a pair key of its own (ignored), and beacons whose key does not name their ID (`bad` on the `lora transfers` line grows), for two minutes while the neighbors trade traffic: no transfer ends early or is delivered from it. Then `reboot` one of two nodes in the middle of traffic: within 45 s (a first beacon up to 12 s after boot, then a reply up to 30 s after it) both hold the key again (`from unknown nodes` stops growing), and neither holds the other down.
- Answers under load: three tier-1 boards in mutual range, each with a phone posting text every few seconds, for ten minutes. Compare each node's `frame in` log against what its neighbors sent it: with no loss on the bench, pieces arriving twice mean an answer came after the sender's feedback wait, because the receiver was holding its own frame in channel check or backoff. Record the share; above about 5 %, an answer should pre-empt a frame not yet on air.
- A phone forced to a 23-byte MTU (a test app, or an old Android): nothing crosses either way, since no bitchat frame or fragment fits 20 bytes (a fragment needs at least 101), as with any bitchat client; the node holds the slot until 45 s of silence drops it. Record that the node stays up and frees the slot.
- One slow phone among fast ones: a phone holding a long connection interval or no LE Data Length Extension beside three that stream live video. NimBLE's host send buffers (`BT_NIMBLE_MSYS_1`, about four full frames on the S3) are shared by every link: record `tx`, `events dropped` and the other phones' latency, and whether a node dial still forms. If the slow link throttles the rest, raise `BT_NIMBLE_MSYS_1_BLOCK_COUNT` and measure again.
- Each board's own parts from a full power removal: the Heltec V4-R8's OLED lights (Vext on GPIO40, taken to be active low like the V4's), the T-Beam Supreme's display lights (ALDO1, at 0x3C or, on some revisions, 0x3D), and a scratch build printing `uxTaskGetStackHighWaterMark` for the mesh, lora, NimBLE host, display and console tasks after S11's load shows each keeps at least 1 KiB.
- A malformed-frame flood from a test tool, and 30 % LoRa loss (an attenuator, or the far board half-shielded).
- The radio reset alone: on a tier-1 board, pull the SX1262's NRESET low for a moment (a wire to ground at its pin or test pad) while the node only listens, and again while it sends. Within 5 s the console logs `radio lost its setup` or `radio left receive on its own` and then `radio recovered`, frames flow both ways again, and a second receiver or a spectrum analyzer sees nothing sent off the region's channel or in another modulation.
- A reset loop on LoRa: with a node sending all it can (a phone posting every second), `reboot` it and brown it out (a bench supply lowered below the brownout threshold and back) several times within an hour; a panic restarts the chip as `reboot` does. Each boot logs `duty ledger carried over the reset`, `status` airtime keeps climbing across the resets rather than starting at 0, and over the hour the radio's time on air (a second receiver logging every frame) stays under the region's budget. Then, after that hour of full use, cut the power and restore it at once: the log says `restored from flash`, and over the hour around the cut the time on air stays within the budget and a sixty-first of it. A board with the ledger never written (erase its settings partition first) logs `taken as spent`, and its first beacon waits until the first minute ends.
- A manifest flood: a test node (a dev build announcing `0xB1` bit 0) bound to a node with an owner key, sending garbage 125-byte OTA manifests as fast as its link takes them for two minutes, then the same with valid signed board posts or deposits. `status`'s `longest mesh pass` before and after; the console log for a watchdog panic.
- Lost control events: on a dev build with `AH_EVENT_QUEUE` at its minimum (8), connect two phones at once while the node hashes its image (send it a manifest for its own version from the test node). Each phone must get the node's announce within a few seconds, and `status` must show both links bound. Then the same on a LoRa node with its trunk queue kept full (a phone across the trunk posting every second) while it hashes: its LoRa link must take packets again within a second of the stall, and the posts keep crossing.
- Factory reset under traffic: `factory-reset yes` while a phone deposits mail and the clock is synced. After the reboot, `status` shows a new peer ID, no owner key, `mail stored 0`, and `crash` shows none stored.

Pass: no crash (no reboot in `status`'s uptime), no corrupt store, OTA rolls back, ARQ recovers, relaying continues. `longest mesh pass` stays under 5 s (the watchdog panics at 10 s; [ARCHITECTURE.md](ARCHITECTURE.md) gives the estimate), and record it with the board.

#### S14. OTA Across Three Nodes

1. Three nodes of one board on version N, all provisioned with one owner key; a phone near each (to check nothing reaches it).
2. Flash a fourth node of the same board with version N+1 and its manifest ([OTA.md](OTA.md), "Seeding the First Node").
3. Watch the update spread node to node. Then try: a downgrade (N-1 manifest), a manifest signed by another key, a manifest for another board.
4. Offer one node a deliberately broken N+2 (one that crashes at boot) and let it roll back; the boot log says `versions up to` N+2 `are refused`. Then start an N+3 transfer to it and cut its power halfway. After it boots, a neighbor still serving N+2 must not be fetched from again (no `fetching image` for N+2 in the log).
5. Offer one node an N+4 that crashes five minutes after boot (an `abort()` behind a timer in a scratch build): with a phone bound, it must still roll back, since a trial lasts `AH_OTA_TRIAL_MIN` (15 minutes) with a bound link, and no neighbor may be offered N+4 while it is on trial.
6. A test node announcing `0xB1` bit 0 offers a newer version and answers each request with a 1-byte chunk, or with garbage, while an honest node offers the same version: the target must finish from the honest node within the hour (`update from a slow server given up` after about a minute, or the hash refused for that server alone). Then have the test node drop the link 30 s into each transfer and offer again on reconnecting: the target holds it off after the first and finishes from the honest node.

Pass: spreads node to node; downgrade, bad signature and foreign fleet refused; a version rolled back from stays refused across an interrupted transfer and a reboot; zero OTA packets relayed by phones (the sniffer sees `0xA0` to `0xA3` only on node-to-node links, and never from a phone). An image crashing minutes after boot rolls back rather than spreading; a slow or lying server never holds an update off. After the broken image, `status` gives `last reset crash` and `crash` its task and backtrace, on a release board too.

#### S15. 72 h Soak with Phones Coming and Going

Two nodes, phones arriving and leaving through the day, a scripted sender posting every minute. `status` every hour.

Pass: zero resets (uptime keeps growing); minimum heap stable; no table grows unbounded (`peers` steady, and the `short of` counters and `events dropped` not climbing).

#### S16. Power Profile

Measure the average current in each state: idle, a phone connected, traffic, LoRa receiving, LoRa transmitting. Measure each with frequency scaling on, as shipped, and again with the CPU held at its default clock, so the saving is known. Then, one at a time, try what is left off until measured: Bluetooth controller sleep (on the S3 `CONFIG_BT_CTRL_MODEM_SLEEP` with `CONFIG_BT_CTRL_LPCLK_SEL_MAIN_XTAL`, since none of the boards has a 32 kHz crystal; on the C6 `CONFIG_BT_LE_SLEEP_ENABLE`), and automatic light sleep with the SX1262's DIO1 armed as a wake source. Keep one only if phones stay connected, LoRa frames are still received, and S1 and S4 still pass.

Pass: average current per state documented; one configuration fits the solar budget (a 1 W panel at 4 peak sun hours yields about 4 Wh a day, so the node must average under about 45 mA at 3.7 V with margin).

#### S17. The US and Australian Profiles on a Spectrum Analyzer

A tier-1 board provisioned `us`, the antenna port cabled through an attenuator to a spectrum analyzer, sending all it can (a phone posting every second, the far node in reach). At the power `status` reports, measure the 6 dB bandwidth and the power spectral density in 3 kHz, once with KDB 558074's peak method (PKPSD: 3 kHz resolution, peak detector, max hold) and once with an average method (AVGPSD: RMS detector, trace averaging over at least 100 sweeps).

Pass: a 6 dB bandwidth of at least 500 kHz, and the average density at most 8 dBm in 3 kHz, with the margin recorded. Record the peak reading as well: if it is over 8 dBm, the profile's compliance rests on the average method ([LORA.md](LORA.md), "What Cannot Comply"), and an `anz` board's radiated density against 14 dBm in 3 kHz needs the same two readings.

### Coded PHY

`AH_BLE_CODED_PHY` (off by default) asks node-to-node links for LE Coded PHY. To turn it on by default, two nodes with it enabled must, at a distance where 1M PHY drops, keep their link and carry S1's traffic, with the logs showing the PHY change.

### Sending Results

For each scenario: the boards and phones with versions, the setup (distances, walls), the measured values against the pass bar, the `status` before and after, and the console logs.
