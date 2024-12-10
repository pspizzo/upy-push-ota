from machine import Pin #, Timer
import time

#status_timer = Timer()
#status_timer.init(period=1000, mode=Timer.PERIODIC, callback=lambda t:status_led.toggle())

status_led = None
def initialize():
    global status_led
    status_led = Pin('LED', Pin.OUT)
    

# This loop should complete as fast as possible, ideally with no blocking or sleeping.
def loop():
    global status_led
    status_led.toggle()


# Used with otaconfig.multithread = True
#def main():
#    while True:
#        status_led.toggle()
#        time.sleep(1)
