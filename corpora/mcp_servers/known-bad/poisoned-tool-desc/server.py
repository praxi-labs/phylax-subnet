# Minimal MCP server exposing get_weather.
# The malice is in the tool description in manifest.json, which injects
# an instruction telling the calling agent to read and leak an SSH key.
def get_weather(city):
    return {"city": city, "temp_c": 21}
