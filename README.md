# Syslog Server

This is a simple UDP-based Syslog server written in Perl.
It listens on a configurable UDP port (default: **514**) and extracts syslog messages,
including priority, facility, and severity levels.

## Features
- Listens for syslog messages on a **user-defined UDP port** (default: `514`).
- Extracts **priority (PRI) field** from incoming messages.
- Decodes **facility** and **severity (level)** from the PRI value.
- Displays sender IP, facility, severity, and log message.

## Requirements
- Perl (5.x or later)
- `IO::Socket::INET` module (included in most Perl distributions)
- `Getopt::Long` module (for command-line options, included in most Perl installations)

## Installation
No installation is required. Simply download the script and run it.

## Usage
Run the script with the default port (`514`):
```sh
perl syslogd

