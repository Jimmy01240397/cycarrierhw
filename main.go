package main

import (
    "os"

    "cycarrierhw/router"
)

func main() {
    router.Setup(os.Args[0])
    router.Run(os.Args[1:])
}
