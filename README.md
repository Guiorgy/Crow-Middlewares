# Crow Middlewares

A set of useful middlewares for the [Crow microframework](https://github.com/CrowCpp/Crow).

## Middlewares

### WhitelistIpGuard

Alias of `RemoteIpGuard<allowed_ip_list, true>`.

A middleware that checks if the IP an incomming request comes from is in a comma-separated whitelist, and returns result code 403 Forbidden if it is not.

#### Usage

```c++
// Comma-separated list must be constant
const char allowed_ips[] = "127.0.0.1,127.0.0.2";

int main()
{
    // Pass the comma-separated list as template argument
    crow::App<crow::WhitelistIpGuard<allowed_ips>> app;

    ...
}
```

### DynamicWhitelistIpGuard

Alias of `RemoteIpGuard<nullptr, true>`.

Useful if you want an instance of a `WhitelistIpGuard` middleware that can have IP addresses added/removed in runtime.

#### Usage

```c++
int main()
{
    crow::App<crow::DynamicWhitelistIpGuard> app;
    
    // Get the instance of the DynamicWhitelistIpGuard middleware
    crow::DynamicWhitelistIpGuard& ipGuard = app.get_middleware<crow::DynamicWhitelistIpGuard>();

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

### BlacklistIpGuard

Alias of `RemoteIpGuard<forbidden_ip_list, false>`.

A middleware that checks if the IP an incomming request comes from is in a comma-separated blacklist, and returns result code 403 Forbidden if it is.

#### Usage

```c++
// Comma-separated list must be constant
const char forbidden_ips[] = "127.0.0.1,127.0.0.2";

int main()
{
    // Pass the comma-separated list as template argument
    crow::App<crow::WhitelistIpGuard<forbidden_ips>> app;

    ...
}
```

### DynamicBlacklistIpGuard

Alias of `DynamicBlacklistIpGuard<nullptr, false>`.

Useful if you want an instance of a `BlacklistIpGuard` middleware that can have IP addresses added/removed in runtime.

#### Usage

```c++
int main()
{
    crow::App<crow::DynamicBlacklistIpGuard> app;
    
    // Get the instance of the DynamicBlacklistIpGuard middleware
    crow::DynamicBlacklistIpGuard& ipGuard = app.get_middleware<crow::DynamicBlacklistIpGuard>();

    // Add IPs
    ipGuard.add_ip("127.0.0.1").add_ip("127.0.0.2");
    
    // Check if IP is blacklisted
    if (ipGuard.is_ip_forbidden("127.0.0.2")) {
        // Remove IPs
        ipGuard.remove_ip("127.0.0.2");
    }

    // Check if the blacklist is frozen
    if (!ipGuard.is_frozen()) {
        // Freeze the blacklist. Subsequent attempts to modify the blacklist will do nothing
        ipGuard.freeze();
    }

    // Will do nothing (except log to CROW_LOG_DEBUG) since the blacklist was frozen above
    ipGuard.add_ip("127.0.0.2");
    
    ...
}
```
