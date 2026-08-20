# route-watch

Monitor de la tabla de rutas IPv4/IPv6 de Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/route` y `/proc/net/ipv6_route` para mostrar destinos, gateways,
máscaras/prefijos, flags (UG/H/…), métricas e interfaces — con defaults resaltados.

## Features

- **IPv4**: decodifica hex little-endian del kernel a dotted-quad + prefijo desde genmask
- **IPv6**: decodifica hex network-order (`%pi6`) con compresión `::`
- **Flags**: UG (up+gateway), H (host), R/D/M y subset IPv6 (A/C/e/r…)
- **Defaults**: resalta rutas `default` y cuenta gateways / host routes
- **Watch mode**: refresco periódico con deltas de conteo entre snapshots
- **JSON output**: snapshot completo (`summary` + arrays `ipv4`/`ipv6`)
- **Demo mode**: tabla multi-iface sintética (eth0, docker0, wg0, tun0…)
- **--ipv4 / --ipv6**: filtrar familia
- **--no-color**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 44 checks (decode, parser, demo, JSON, /proc real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o route-watch
```

## Usage

```bash
# Snapshot único (tabla real del host)
./route-watch

# Modo watch (cada 2s)
./route-watch --watch 2

# Solo IPv4 / solo IPv6
./route-watch --ipv4
./route-watch --ipv6

# JSON
./route-watch --json

# Demo (tabla sintética multi-iface)
./route-watch --demo

# Sin colores
./route-watch --no-color

# Auto-tests
./route-watch --selftest
```

## Data Source

| Archivo | Campos |
|---------|--------|
| `/proc/net/route` | Iface, Destination, Gateway, Flags, RefCnt, Use, Metric, Mask (hex LE) |
| `/proc/net/ipv6_route` | dest, prefixlen, src, gateway, metric, refcnt, use, flags, iface (hex BE `%pi6`) |

### Decodificación IPv4

El kernel imprime cada `__be32` con `%08X` en host little-endian. Ejemplo real:

- `010110AC` → bytes LSB-first → `172.16.1.1`
- `00FFFFFF` → `255.255.255.0` → prefijo `/24`

### Decodificación IPv6

`ipv6_route` usa `%pi6` (32 hex chars en **orden de red**), distinto de `/proc/net/tcp6`
(que imprime palabras LE). Ejemplo:

- `00000000000000000000000000000001` → `::1`
- `20010db8000000000000000000000000` → `2001:db8::`

## Example Output

```
+================================================+
|     Linux Routing Table Monitor               |
+================================================+
  Source: /proc/net/route + ipv6_route

  -- Aggregate --
  IPv4 routes    7
  IPv6 routes    5
  Default v4     2
  Default v6     1
  Via gateway    3
  Host routes    1

  -- IPv4 routes (7) --
  Iface    Destination        Gateway          Flg  Metric Genmask
  eth0     default            172.16.1.1       UG      100 0.0.0.0
  eth0     172.16.1.0/24      *                U         0 255.255.255.0
  ...
```

## License

MIT
