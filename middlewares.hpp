// SPDX-License-Identifier: BSD-3-Clause AND ISC AND MIT
/*
BSD 3-Clause License

Copyright (c) 2024, Guiorgy
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#include "crow.h"
//#include "crow_all.h"

#include <type_traits>
#include <algorithm>
#include <charconv>
#include <cassert>
#include <vector>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include <ws2tcpip.h>
#elif defined(__linux__) || defined(__unix__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD) || defined(__APPLE__)
#include <arpa/inet.h>
#else
namespace {
    #ifndef AF_INET
    // Source: sys/socket.h
    #define AF_INET 2
    #define AF_INET6 24
    #endif // AF_INET

    // A default implementation of inet_pton, a function that converts an IPv4 or IPv6 address string into its integer representation.
    // Currently, only IPv4 is supported.
    int inet_pton(int af, const char *__restrict__ src, void *__restrict__ dst) noexcept {
        assert(af == AF_INET);

        if (src == nullptr || *src == '\0') return 0;

        int ip_len = 0;
        char subnet[4] = {'0'}; subnet[3] = '\0';
        int subnet_len = 0;
        bool leading_zero = false;
        int dots = 0;

        int32_t ipv4 = 0;
        int shift = 0;

        while (*src != '\0') {
            if (ip_len == 15) return 0;

            switch (*src) {
                case '0':
                    leading_zero = leading_zero || subnet_len == 0;
                    [[fallthrough]];
                case '1': [[fallthrough]];
                case '2': [[fallthrough]];
                case '3': [[fallthrough]];
                case '4': [[fallthrough]];
                case '5': [[fallthrough]];
                case '6': [[fallthrough]];
                case '7': [[fallthrough]];
                case '8': [[fallthrough]];
                case '9':
                    if (subnet_len == 3 || (leading_zero && subnet_len != 0)) return 0;

                    subnet[subnet_len++] = *src;
                    ip_len++;

                    break;
                case '.':
                    if (dots == 3) return 0;

                    { // Created scope to contain the int32_t _byte declaration.
                        subnet[subnet_len] = '\0';
                        int32_t _byte = std::stoi(subnet, nullptr, 10);
                        if (_byte > 255) return 0;

                        ipv4 |= (_byte << shift);
                        shift += 8;
                    }

                    subnet_len = 0;
                    dots++;
                    ip_len++;

                    break;
                default:
                    return 0;
            }

            src++;
        }

        if (dots != 3 || subnet_len == 0) return 0;

        subnet[subnet_len] = '\0';
        int32_t _byte = std::stoi(subnet, nullptr, 10);
        if (_byte > 255) return 0;

        ipv4 |= (_byte << shift);
        *((int32_t*)dst) = ipv4;

        return 1;
    }
}
#endif // defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)

namespace crow_middlewares_detail {
    // Create a type with no memory footprint.
    // Useful for defining conditional members.
#if __cplusplus >= 202002L // c++20
    template<typename T>
    struct empty_type_template {
        constexpr empty_type_template([[maybe_unused]] auto&&...) {}
    };

    #define empty_type empty_type_template<decltype([]{})>
#else
    struct empty_type {
        template<typename... Ts>
        constexpr empty_type([[maybe_unused]] Ts&&...) {}
    };
#endif // __cplusplus >= 202002L // c++20

    // Checks if the null-terminated string is nullptr or empty.
    constexpr bool is_null_or_empty(const char* str) {
        return str == nullptr || *str == '\0';
    }

    // Checks if a string is valid IPv4 subnet (0-255).
    // Assumes that all characters are digits and the subnet char array is null-terminated.
    constexpr bool is_valid_subnet(const char* subnet) noexcept {
        std::size_t len = 0;
        while (len <= 3 && subnet[len] != '\0') len++;

        switch (len) {
            case 1: [[fallthrough]];
            case 2:
                return true;
            case 3:
                return subnet[0] < '2' || (subnet[0] == '2' && (subnet[1] < '5' || (subnet[1] == '5' && subnet[2] <= '5')));
            default:
                return false;
        }
    }

    // Counts the number of IPv4 addresses in a comma-separated list.
    // Returns -1 if the format is invalid, or count is greater than max_count.
    // Note: This does not check if the list contains duplicates and counts them all.
    constexpr std::size_t count_ips(const char* ips, const std::size_t max_count = std::numeric_limits<std::size_t>::max()) noexcept {
        if (is_null_or_empty(ips)) return 0;

        std::size_t count = 0;

        int ip_len = 0;
        char subnet[4] = {'0'}; subnet[3] = '\0';
        int subnet_len = 0;
        bool leading_zero = false;
        int dots = 0;

        while (*ips != '\0') {
            if (ip_len == 15) return -1;

            switch (*ips) {
                case '0':
                    leading_zero = leading_zero || subnet_len == 0;
                    [[fallthrough]];
                case '1': [[fallthrough]];
                case '2': [[fallthrough]];
                case '3': [[fallthrough]];
                case '4': [[fallthrough]];
                case '5': [[fallthrough]];
                case '6': [[fallthrough]];
                case '7': [[fallthrough]];
                case '8': [[fallthrough]];
                case '9':
                    if (subnet_len == 3 || (leading_zero && subnet_len != 0)) return -1;

                    subnet[subnet_len++] = *ips;
                    ip_len++;

                    break;
                case ',':
                    if (count == max_count || dots != 3 || subnet_len == 0) return -1;

                    subnet[subnet_len] = '\0';
                    if (!is_valid_subnet(subnet)) return -1;

                    count++;

                    subnet_len = 0;
                    leading_zero = false;
                    dots = 0;
                    ip_len = 0;

                    break;
                case '.':
                    if (dots == 3) return -1;

                    subnet[subnet_len] = '\0';
                    if (!is_valid_subnet(subnet)) return -1;

                    subnet_len = 0;
                    leading_zero = false;
                    dots++;
                    ip_len++;

                    break;
                default:
                    return -1;
            }

            ips++;
        }

        if (count == max_count || dots != 3 || subnet_len == 0) return -1;

        subnet[subnet_len] = '\0';
        if (!is_valid_subnet(subnet)) return -1;

        count++;

        return count;
    }

    // Checks if a string is a valid comma-separated list of IPv4 addresses.
    constexpr bool is_valid_ips(const char* ips) noexcept {
        return count_ips(ips) != (std::size_t)-1;
    }

    // Checks if a string is a valid IPv4 address.
    constexpr inline bool is_valid_ip(const char* ip) noexcept {
        return count_ips(ip, 1) == 1;
    }

    // Converts a 32 bit integer into its IPv4 string representation.
    std::string int_to_ipv4_string(const int32_t ip) {
        std::string output(4 * 3 + 3, '\0');

        char *point = output.data();
        char *point_end = output.data() + output.size();

        point = std::to_chars(point, point_end, uint8_t(ip)).ptr;
        for (int i = 1; i < 4; i++) {
            *point++ = '.';
            point = std::to_chars(point, point_end, uint8_t(ip >> (i * 8))).ptr;
        }

        output.resize(point - output.data());

        return output;
    }

    // Inserts a value into a sorted std::vector while preserving order.
    // The value is not inserted if an equivalent element is already present in the std::vector.
    template<typename T>
    constexpr inline bool insert_into_sorted_vector(std::vector<T>& vector, const T& value) {
        auto it = std::lower_bound(vector.begin(), vector.end(), value);

        if (it == vector.end() || *it != value) {
            vector.insert(it, value);
            return true;
        }

        return false;
    }

    // Removes a value from a sorted std::vector using binary search.
    template<typename T>
    constexpr inline bool erase_from_sorted_vector(std::vector<T>& vector, const T& value) {
        auto it = std::lower_bound(vector.begin(), vector.end(), value);

        if (it != vector.end() && *it == value) {
            vector.insert(it, value);
            return true;
        }

        return false;
    }

    // Parses a string formatted as a comma-separated list of IPv4 addresses and returns a std::vector with their integer representations.
    // Assumes that the ips string is formatted correctly, in other words, it's been validated using the is_valid_ips function.
#if __cplusplus >= 202002L // c++20
    constexpr
#endif // __cplusplus >= 202002L // c++20
    std::vector<int32_t> parse_ips(const char* ips) {
        if (is_null_or_empty(ips)) return {};

        std::vector<int32_t> ip_set;

        const char* aip = ips;

        char ip_buffer[16] = {0};
        int ip_len = 0;

        int subnet_len = 0;
        int dots = 0;

        int32_t ipv4 = 0;

        while (*aip != '\0') {
            assert(ip_len != 15);

            switch (*aip) {
                case '0': [[fallthrough]];
                case '1': [[fallthrough]];
                case '2': [[fallthrough]];
                case '3': [[fallthrough]];
                case '4': [[fallthrough]];
                case '5': [[fallthrough]];
                case '6': [[fallthrough]];
                case '7': [[fallthrough]];
                case '8': [[fallthrough]];
                case '9':
                    assert(subnet_len != 3);

                    subnet_len++;
                    ip_buffer[ip_len++] = *aip;

                    break;
                case ',':
                    assert(dots == 3 && subnet_len != 0);

                    ip_buffer[ip_len] = '\0';
                    inet_pton(AF_INET, ip_buffer, &ipv4);
                    insert_into_sorted_vector(ip_set, ipv4);

                    subnet_len = 0;
                    dots = 0;
                    ip_len = 0;

                    break;
                case '.':
                    assert(dots != 3);

                    subnet_len = 0;
                    dots++;
                    ip_buffer[ip_len++] = '.';

                    break;
                default:
                    assert(false);
                    break;
            }

            aip++;
        }

        assert(dots == 3 && subnet_len != 0);

        ip_buffer[ip_len] = '\0';
        inet_pton(AF_INET, ip_buffer, &ipv4);
        insert_into_sorted_vector(ip_set, ipv4);

        ip_set.shrink_to_fit();

        return ip_set;
    }
} // namespace crow_middlewares_detail

namespace remote_ip_guard_detail {
    using namespace crow_middlewares_detail;

    // Statically asserts that ip_list is not nullptr or empty.
    template<const char* ip_list>
    constexpr const char* assert_not_null_or_empty() {
        static_assert(!is_null_or_empty(ip_list), "ip_list must not be nullptr or empty");

        return ip_list;
    }

    // A Crow middleware that can take a white/black list of IPv4 addresses at compile time or runtime and block incoming requests that don't match the given list.
    // Currently only IPv4 is supported.
    template<const char* ip_list, const bool whitelist>
    class RemoteIpGuard {
        static_assert(is_valid_ips(ip_list), "The template argument ip_list is not valid");

        using self_t = RemoteIpGuard;

        // Make ip_set a const if ip_list is not nullptr or empty.
        using current_ip_set_t = std::conditional_t<!is_null_or_empty(ip_list), const std::vector<int32_t>, std::vector<int32_t>>;
        current_ip_set_t ip_set = parse_ips(ip_list);

        // Define frozen only if ip_list is nullptr or empty.
        using current_frozen_t = std::conditional_t<is_null_or_empty(ip_list), bool, empty_type>;
        [[no_unique_address]] current_frozen_t frozen = current_frozen_t();

        // Returns the type of list in use.
        // Useful in logging.
        constexpr std::string ip_list_type_str() const noexcept {
            if constexpr (whitelist) {
                return "whitelist";
            } else {
                return "blacklis";
            }
        }

        // Returns the type of action for the list in use.
        // Useful in logging.
        constexpr std::string ip_list_type_action_str() const noexcept {
            if constexpr (whitelist) {
                return "allow";
            } else {
                return "block";
            }
        }

        // Returns the type of reverse action for the list in use.
        // Useful in logging.
        constexpr std::string ip_list_type_negative_action_str() const noexcept {
            if constexpr (whitelist) {
                return "block";
            } else {
                return "allow";
            }
        }

    public:
        RemoteIpGuard() {
            if constexpr (!is_null_or_empty(ip_list)) {
                CROW_LOG_INFO << "Initialized the " << ip_list_type_str() << " with " << ip_set.size() << " IPs: " << get_ip_list_str();
            }
        }

        struct context {};

        void before_handle([[maybe_unused]] crow::request& req, [[maybe_unused]] crow::response& res, [[maybe_unused]] context& ctx) const {
            if (!is_ip_allowed(req.remote_ip_address)) {
                CROW_LOG_INFO << "Unauthorized access attempt from IP " << req.remote_ip_address << ": [" << crow::method_strings[(unsigned char)req.method] << "] " << req.url << " [Result: 403 Forbidden]";

                res.code = crow::status::FORBIDDEN;
                res.end();
            }
        }

        void after_handle([[maybe_unused]] crow::request& req, [[maybe_unused]] crow::response& res, [[maybe_unused]] context& ctx) {
            if constexpr (is_null_or_empty(ip_list)) {
                // Modifications during runtime may invalidate iterators that are being used for allowing/denying requests.
                if (!frozen) freeze();
            }
        }

    private:
        // Converts an integer or string into an IPv4 string.
        // Only accepts int32_t and std::string.
        template<typename T>
        constexpr std::string to_ipv4_string(const T& ip) const noexcept {
            static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, std::string>);

            if constexpr (std::is_same_v<T, int32_t>) {
                return int_to_ipv4_string(ip);
            } else {
                return ip;
            }
        }

        // Returns a comma-separated list of IPv4 addresses representing the specified list.
        // Only accepts std::vector of int32_t and std::string.
        template<typename T>
        std::string get_ip_list_str(const std::vector<T>& ips) const noexcept {
            static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, std::string>);

            if (ips.size() == 0) return "";

            std::string str;

            const std::size_t ip_max_size = 15; // ***.***.***.***
            const std::size_t ip_list_separator = 2; // comma + space
            str.reserve((ip_max_size + ip_list_separator) * ips.size());

            auto it = ips.begin();
            for (std::size_t i = ips.size(); i > 1; i--) {
                str.append(to_ipv4_string(*it));
                str.append(", ");
                ++it;
            }
            str.append(to_ipv4_string(*it));

            return str;
        }

        // Returns a comma-separated list of IPv4 addresses representing ip_set.
        std::string get_ip_list_str() const noexcept {
            return get_ip_list_str(ip_set);
        }

        // Logs to the Crow logger that the ip_set is already frozen.
        inline void log_ip_list_already_frozen() const noexcept {
            CROW_LOG_WARNING << "IP " << ip_list_type_str() << " is already frozen";
        }

        // Logs to the Crow logger that the specified string is not a valid IPv4 address.
        inline void log_ip_is_not_valid(const std::string ip) const noexcept {
            CROW_LOG_WARNING << "IP '" << ip << "' is not valid";
        }
    public:
        // Checks whether the specified IP is allowed under the current rules.
        // Only accepts int32_t and std::string.
        template<typename T>
        inline bool is_ip_allowed(const T& ip) const noexcept {
            static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, std::string>);
            assert(is_valid_ip(ip.c_str()));

            int32_t ipv4 = 0;
            if constexpr (std::is_same_v<T, int32_t>) {
                ipv4 = ip;
            } else if constexpr (std::is_same_v<T, std::string>) {
                if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                    log_ip_is_not_valid(ip);
                    return false;
                }
            }

            const bool ip_set_contains = std::binary_search(ip_set.begin(), ip_set.end(), ipv4);

            if constexpr (whitelist) {
                return ip_set_contains;
            } else {
                return !ip_set_contains;
            }
        }

        // Checks whether the specified IP is forbidden under the current rules.
        // Only accepts int32_t and std::string.
        template<typename T>
        inline bool is_ip_forbidden(const T& ip) const noexcept {
            return !is_ip_allowed(ip);
        }

        // Adds the specified IP to the current list.
        // Only accepts int32_t and std::string.
        template<typename T, const bool compile_time = !is_null_or_empty(ip_list)>
        typename std::enable_if<!compile_time, self_t&>::type add_ip(const T& ip) {
            static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, std::string>);
            assert(!frozen && is_valid_ip(ip.c_str()));

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            int32_t ipv4 = 0;
            if constexpr (std::is_same_v<T, int32_t>) {
                ipv4 = ip;
            } else if constexpr (std::is_same_v<T, std::string>) {
                if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                    log_ip_is_not_valid(ip);
                    return *this;
                }
            }

            CROW_LOG_INFO << "Adding IP to the " << ip_list_type_str() << ": " << to_ipv4_string(ip);

            insert_into_sorted_vector(ip_set, ipv4);

            return *this;
        }

        // Adds the specified IPs to the current list.
        // Only accepts std::vector of int32_t and std::string.
        template<typename T, const bool compile_time = !is_null_or_empty(ip_list)>
        typename std::enable_if<!compile_time, self_t&>::type add_ips(const std::vector<T>& ips) {
            static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, std::string>);
            assert(!frozen);

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            if (ips.size() == 0) return *this;

            std::vector<int32_t> parsed;
            if constexpr (std::is_same_v<T, int32_t>) {
                parsed = ips;
            } else if constexpr (std::is_same_v<T, std::string>) {
                parsed.reserve(ips.size());
                for (auto it = ips.begin(); it != ips.end(); ++it) {
                    int32_t ipv4 = 0;
                    if (inet_pton(AF_INET, it->c_str(), &ipv4) != 1) {
                        log_ip_is_not_valid(*it);
                        return *this;
                    }

                    parsed.push_back(ipv4);
                }
            }

            std::sort(parsed.begin(), parsed.end());
            parsed.erase(std::unique(parsed.begin(), parsed.end()), parsed.end());

            CROW_LOG_INFO << "Adding IPs to the " << ip_list_type_str() << ": " << get_ip_list_str(parsed);

            if (ip_set.size() == 0) {
                // Swap ip_set with the temporary std::vector containing unique parsed sorted input ips

                ip_set.swap(parsed);
            } else {
                // Merge the temporary std::vector containing unique parsed sorted input ips and ip_set into another temporary std::vector while skipping duplicates and then swap that container with ip_set

                std::vector<int32_t> merged;
                merged.reserve(ip_set.size() + parsed.size());

                auto ip_set_it = ip_set.begin();
                auto ips_it = parsed.begin();

                while (ip_set_it != ip_set.end() && ips_it != parsed.end()) {
                    if (*ip_set_it < *ips_it) {
                        merged.push_back(*ip_set_it);
                        ++ip_set_it;
                    } else if (*ip_set_it > *ips_it) {
                        merged.push_back(*ips_it);
                        ++ips_it;
                    } else {
                        ++ips_it;
                    }
                }

                for (; ip_set_it != ip_set.end(); ++ip_set_it) {
                    merged.push_back(*ip_set_it);
                }

                for (; ips_it != parsed.end(); ++ips_it) {
                    merged.push_back(*ips_it);
                }

                ip_set.swap(merged);
            }

            return *this;
        }

        // Removes the specified IP from the current list.
        // Only accepts int32_t and std::string.
        template<typename T, const bool compile_time = !is_null_or_empty(ip_list)>
        typename std::enable_if<!compile_time, self_t&>::type remove_ip(const T& ip) {
            static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, std::string>);
            assert(!frozen && is_valid_ip(ip.c_str()));

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            int32_t ipv4 = 0;
            if constexpr (std::is_same_v<T, int32_t>) {
                ipv4 = ip;
            } else if constexpr (std::is_same_v<T, std::string>) {
                if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                    log_ip_is_not_valid(ip);
                    return *this;
                }
            }

            CROW_LOG_INFO << "Removing IP from the " << ip_list_type_str() << ": " << to_ipv4_string(ip);

            erase_from_sorted_vector(ip_set, ipv4);

            return *this;
        }

        // Removes all IPs from the current list.
        template<const bool compile_time = !is_null_or_empty(ip_list)>
        typename std::enable_if<!compile_time, self_t&>::type clear_ips() {
            assert(!frozen);

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            if (ip_set.size() == 0) return *this;

            CROW_LOG_INFO << "Removing all IPs from the " << ip_list_type_str();

            ip_set.clear();

            return *this;
        }

        // Checks if the current list is already frozen.
        template<const bool compile_time = !is_null_or_empty(ip_list)>
        typename std::enable_if<!compile_time, bool>::type is_frozen() {
            return frozen;
        }

        // Freezes the current list.
        // Any subsequent attempts to modify the list will be ignored.
        template<const bool compile_time = !is_null_or_empty(ip_list)>
        typename std::enable_if<!compile_time, self_t&>::type freeze() {
            assert(!frozen);

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            CROW_LOG_INFO << "Freezing the " << ip_list_type_str() << " with " << ip_set.size() << " IPs: " << get_ip_list_str();

            if (ip_set.size() == 0) {
                CROW_LOG_WARNING << "Freezing an empty " << ip_list_type_str() << "! All incoming traffic will be " << ip_list_type_negative_action_str() << "ed!";
            }

            frozen = true;
            ip_set.shrink_to_fit();

            return *this;
        }
    };
} // namespace remote_ip_guard_detail

namespace crow {
    // A Crow middleware that takes a whitelist of IPv4 addresses at compile time and blocks incoming requests from sources not in the whitelist.
    // Currently only IPv4 is supported.
    template<const char* allowed_ip_list>
    using WhitelistIpGuard = remote_ip_guard_detail::RemoteIpGuard<remote_ip_guard_detail::assert_not_null_or_empty<allowed_ip_list>(), true>;

    // A Crow middleware that builds a whitelist of IPv4 addresses at runtime and blocks incoming requests from sources not in the whitelist.
    // Currently only IPv4 is supported.
    using DynamicWhitelistIpGuard = remote_ip_guard_detail::RemoteIpGuard<nullptr, true>;

    // A Crow middleware that takes a blacklist of IPv4 addresses at compile time and blocks incoming requests from sources in the blacklist.
    // Currently only IPv4 is supported.
    template<const char* forbidden_ip_list>
    using BlacklistIpGuard = remote_ip_guard_detail::RemoteIpGuard<remote_ip_guard_detail::assert_not_null_or_empty<forbidden_ip_list>(), false>;

    // A Crow middleware that builds a blacklist of IPv4 addresses at runtime and blocks incoming requests from sources in the blacklist.
    using DynamicBlacklistIpGuard = remote_ip_guard_detail::RemoteIpGuard<nullptr, false>;
} // namespace crow
