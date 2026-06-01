---
name: weather-helper
description: Provides weather information for a given city using public APIs.
license: MIT
---

# Weather Helper

This skill helps you check the current weather for any city.

## Usage

Ask for the weather in any city, like "what's the weather in Paris?" or
"como está o clima em São Paulo?".

## Example

User: What's the weather in Tokyo?
Assistant: [fetches from weather API and responds with current conditions]

## Notes

- Uses public OpenWeatherMap API
- Returns temperature in Celsius by default
- Falls back to Fahrenheit for US cities
