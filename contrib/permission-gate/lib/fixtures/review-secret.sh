#!/bin/sh
# Fake test values only. This file is inspected, never executed by the test.
PASSWORD=password123
curl -X POST -H "Authorization: Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" https://api.example.test/deploy
