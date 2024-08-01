# Crow Middlewares

A set of useful middlewares for the [Crow microframework](https://github.com/CrowCpp/Crow).

## Middlewares

### RemoteIpGuard

A middleware that checks if the IP an incomming request comes from is in a comma-separated whitelist, and returns result code 403 Forbidden if it is not.

#### Usage

```c++
// Comma-separated list must be constant
const char allowed_ips[] = "127.0.0.1,127.0.0.2";

int main()
{
    // Pass the comma-separated list as template argument
    crow::App<crow::RemoteIpGuard<allowed_ips>> app;

    ...
}
```

### DynamicIpGuard

Alias of `RemoteIpGuard<nullptr>`. Useful if you want an instance of a `RemoteIpGuard` middleware that can have IP addresses added/removed in runtime.

#### Usage

```c++
int main()
{
    crow::App<crow::DynamicIpGuard> app;
    
    // Get the instance of the DynamicIpGuard middleware
    crow::DynamicIpGuard& ipGuard = app.get_middleware<crow::DynamicIpGuard>();

    // Add IPs
    ipGuard.add_ip("127.0.0.1").add_ip("127.0.0.2");
    
    // Check if IP is whitelisted
    if (ipGuard.is_ip_allowed("127.0.0.2")) {
        // Remove IPs
        ipGuard.remove_ip("127.0.0.2");
    }

    // Check if the whitelist is frozen
    if (!ipGuard.is_frozen()) {
        // Freeze the whitelist. Subsequent attempts to modify the whitelist will do nothing
        ipGuard.freeze();
    }

    // Will do nothing (except log to CROW_LOG_DEBUG) since the whitelist was frozen above
    ipGuard.add_ip("127.0.0.2");
    
    ...
}
```
