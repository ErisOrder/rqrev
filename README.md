# rqsrv

Protocol reverse engineering tool and (very very very PoC) server emulator for `Royal Quest` MMORPG.
Project is in very early stage (and probably will stay in it for quite loooong time), but you can actually
enter game world and do some basic actions like character moving or inventory management.

## How to build

Build should be quite straightforward. Just run `cargo build [--release]`

## How to connect server emulator

1. Download game client. Project was tested on version `2962300` and probably will work with newer version as well.
2. Proxy client requests to `127.0.0.1:8008` using SOCKS5 protocol. I use `Proxifier` tool, it works well, but proprietary and not free. You can use trial version or find a replacement.
3. Run compiled executable with args `rqsrv.exe server`
4. Prepare shell script or run game executable directly with args `./rqmain.exe /place base /gateway classic /account-id nik /sign-in-code 0000`.
   `/account-id`s are currently hardcoded and can be found in [src/server/db/mod.rs](src/server/db/mod.rs)
5. Now you should be able to enter character selection screen, and then game world

You can launch several game instances with different `/account-id`s to try player position synchronization.

## How to unpack game resources

You can find some valuable data in unpacked game resources.
You can unpack them using the [RQ.TOC.Tool](https://github.com/Ekey/RQ.TOC.Tool/tree/main) tool.
For convenience I have added localization files with various in-game IDs to the repo. 

## CLI Commands

Server emulator supports a few CLI commands that you can enter through in-game chat.
```
/loc <id>             Teleport character to zero position in location with <id>.
/spawnmob <id> <hp>   Spawn mob with <id> at zero position in current location.
/give <id> <quantity> Give item with <id> in <quantity>.  
```

## Packet tracer/MITM mode

You can launch project in packet tracer mode to connect to original game servers and capture packet exchange.
Packet contents are dumped in binary and partially dissected view.
Game uses custom binary de/serialization format with tag-typed fields and composite structures.
It is not self-describing, so dissection of uknown packets may be wrong.
You can find this format description, I call it RQode, in file [src/rqode_binrw.rs](src/rqode_binrw.rs),
and known game packets (be warned that I may have wrong assumptions on their purpose and structure) in [src/protocol.rs](src/protocol.rs).

You can configure what to show in trace in file [src/ptrace.rs](src/ptrace.rs).
You can configure which packets to drop and on which to stop exchange in file [src/mitm.rs](src/mitm.rs)

To launch packet tracer follow server emulator guide up to p.3:

3. Run compiled executable with args `rqsrv.exe mitm`
4. Launch game normally
5. You should see some output in `rqsrv` stdout

## Disclaimer
Not intended for bots or cheats building. This is purely game preservation project. 
