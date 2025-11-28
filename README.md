# CIDR Watch

CIDR Watch is a small Go-based daemon that monitors InfluxDB access logs and checks remote IPs against a configurable watch list of CIDR ranges (by default in `watch_list.txt`). Matched IPs are recorded in a MySQL table (`audit_ips`) and, optionally, email notifications are sent when a given IP exceeds a configured hit threshold.

Configuration is via environment variables (or a `.env` file for development). See the Development section below for usage and environment options.

In my setup we use an external MySQL server and an external InfluxDB (both outside of Docker).

## Development

### Requirements

- [Golang](https://go.dev/doc/install)

### Environment variables options

You need to set some settings using environment variables, for that we use the `.env` file. You can use the [.env.example](.env.example) file as template:

```sh
cp .env.example .env
```


### Start dev

Either run: `go run .`

Or if you want to have watch mode, use: `gow run .`

### Build binary

Run: `go build .`

### Getting started

Assuming you already fulfilled the requirements above.

1. Clone the project: `git clone git@gitlab.melroy.org:melroy/cidr-watcher.git`
2. Prepare the `.env` (see [.env.example](.env.example) file), like setting the `INFLUX_DB` and `INFLUX_USER` environment variables.
3. To start the bot by executing: `go run .`
