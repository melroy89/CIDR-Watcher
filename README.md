# CIDR Watcher

CIDR Watcher is a small Go-based daemon that monitors InfluxDB access logs and checks remote IPs against a configurable watch list of [CIDR ranges](https://docs.netgate.com/pfsense/en/latest/network/cidr.html) (by default in `watch_list.txt`). Matched IPs are recorded in a MySQL table (`audit_ips`) with additional meta-data and, optionally, email notifications are sent when a given IP exceeds a configured hit threshold.

Configuration is via environment variables (using a `.env` file). See the section below for usage.

In my setup we use an external MySQL server and an external InfluxDB (both outside of Docker).

## Production

### Environment variables options

You need to set some settings using environment variables, for that we use the `.env` file. You can use the [.env.example](.env.example) file as template:

```sh
cp .env.example .env
```

### Example stats query

After the database is getting filled with data from InfluxDB. You can perform simple statistics on the gathered data in MySQL/MariaDB. Like use the following `SELECT` query:

```sql
SELECT
    cidr,
    COUNT(*) AS ip_count,
    SUM(hits) AS total_hits
FROM audit_ips
GROUP BY cidr
ORDER BY total_hits DESC, ip_count DESC;
```

Which should give you some insides of the most troublesome CIDRs.

### Docker Compose

In production we use Docker Compose, see [compose.yaml](compose.yaml) file to start the Docker container.

Start the container using: `docker compose up` or start in the background using: `docker compose up -d`.  
_Note:_ If you installed Docker Compose manually, the script name is `docker-compose` instead of `docker compose`.

---

Instead of using Docker Compose, you could also use `docker run` but that is **not** advised. Anyway, here is an example of `docker run` command:

```sh
docker run -it -v $(pwd)/.env:/app/.env -v $(pwd)/watch_list.txt:/app/watch_list.txt -v /var/run/mysqld/mysqld.sock:/var/run/mysqld/mysqld.sock --rm --add-host=host.docker.internal:host-gateway registry.melroy.org/melroy/cidr-watcher/cidr-watcher:latest
```

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
2. Prepare the `.env` (see [.env.example](.env.example) file), like setting the `INFLUX_DB` and `INFLUX_MEASUREMENT` environment variables.
3. To start the bot by executing: `go run .`
