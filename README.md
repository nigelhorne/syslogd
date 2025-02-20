# Syslog Server

This is a simple UDP-based Syslog server written in Perl.
It listens on UDP port 514 and extracts syslog messages, including priority, facility, and severity levels.

## Features
- Listens for syslog messages on **UDP port 514**.
- Extracts **priority (PRI) field** from incoming messages.
- Decodes **facility** and **severity (level)** from the PRI value.
- Displays sender IP, facility, severity, and log message.

## Requirements
- Perl (5.x or later)
- `IO::Socket::INET` module (included in most Perl distributions)

## Installation
No installation is required. Simply download the script and run it.

## Usage
Run the script with:
```sh
perl syslogd
