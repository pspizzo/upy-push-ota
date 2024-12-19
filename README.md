# upy-push-ota
> MicroPython framework for over-the-air updating

## Features

- Push the files you want to the microcontrollers you want
- Runtime protection - if your new files fail to run or even compile on the microcontroller, the upy-push-ota main loop will still continue to run and accept new, (hopefully) fixed files
- Require cryptographic authorization for requests and new incoming files
- Uses the HTTP protocol for communication
- Network logging options for debugging and troubleshooting

## Details

Why did I write another OTA library for MicroPython? I wanted an OTA library that allowed me to push changes to individual microcontrollers, rather than automatically pull changes from a central location. I have used Arduino OTA in the past, and I wanted a similar solution.

[All existing libraries](https://pypi.org/project/micropython-ota/) [that I could find](https://github.com/mkomon/uota) [require pulling changes](https://github.com/rdehuyss/micropython-ota-updater) [from a central](https://github.com/RangerDigital/senko) Github repository or HTTP server.

