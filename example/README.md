# skytap as a product

This directory is not a second binary. Run the module root:

```bash
cd ../
go build -o skytap .
./skytap -listen :3128 -admin 127.0.0.1:8080 -data ./data -install-rules=false
```

Then open http://127.0.0.1:8080/

Libraries (do not import skytap from other programs — import these instead):

- [`github.com/SkyFetch0/skydst`](../../skydst)
- [`github.com/SkyFetch0/gomitm`](../../gomitm)
