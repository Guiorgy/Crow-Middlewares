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

                    { // Created scope to contain the int32_t _byte declaration
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
#if __cplusplus >= 202002L
    template<typename T>
    struct empty_type_template {
        constexpr empty_type_template(auto&&...) {}
    };

    #define empty_type empty_type_template<decltype([]{})>
#else
    struct empty_type {
        constexpr empty_type() {}

        template<typename T>
        constexpr empty_type([[maybe_unused]] T _) {}

        template<typename T1, typename T2>
        constexpr empty_type([[maybe_unused]] T1 _, [[maybe_unused]] T2 __) {}

        template<typename T1, typename T2, typename T3>
        constexpr empty_type([[maybe_unused]] T1 _, [[maybe_unused]] T2 __, [[maybe_unused]] T2 ___) {}
    };
#endif // __cplusplus >= 202002L

    constexpr bool is_empty(const char* str) {
        return str == nullptr || *str == '\0';
    }

    // Assumes that all characters are digits and the subnet char array ends in a null character
    constexpr bool is_valid_subnet(const char* subnet) noexcept {
        size_t len = 0;
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

    constexpr bool is_valid_ips(const char* ips, const bool can_be_null_or_empty = true, const bool can_be_list = true) noexcept {
        assert(!can_be_null_or_empty || can_be_list); // A single empty or nullptr IP makes no sense
        if (is_empty(ips)) return can_be_null_or_empty;

        int ip_len = 0;
        char subnet[4] = {'0'}; subnet[3] = '\0';
        int subnet_len = 0;
        bool leading_zero = false;
        int dots = 0;

        while (*ips != '\0') {
            if (ip_len == 15) return false;

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
                    if (subnet_len == 3 || (leading_zero && subnet_len != 0)) return false;

                    subnet[subnet_len++] = *ips;
                    ip_len++;

                    break;
                case ',':
                    if (!can_be_list || dots != 3 || subnet_len == 0) return false;

                    subnet[subnet_len] = '\0';
                    if (!is_valid_subnet(subnet)) return false;

                    subnet_len = 0;
                    leading_zero = false;
                    dots = 0;
                    ip_len = 0;

                    break;
                case '.':
                    if (dots == 3) return false;

                    subnet[subnet_len] = '\0';
                    if (!is_valid_subnet(subnet)) return false;

                    subnet_len = 0;
                    leading_zero = false;
                    dots++;
                    ip_len++;

                    break;
                default:
                    return false;
            }

            ips++;
        }

        if (dots != 3 || subnet_len == 0) return false;

        subnet[subnet_len] = '\0';
        if (!is_valid_subnet(subnet)) return false;

        return true;
    }

    constexpr inline bool is_valid_ip(const char* ip) noexcept {
        return is_valid_ips(ip, false, false);
    }

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

    template<typename T>
    constexpr inline bool insert_into_sorted_vector(std::vector<T>& vector, const T& value) {
        auto it = std::lower_bound(vector.begin(), vector.end(), value);

        if (it == vector.end() || *it != value) {
            vector.insert(it, value);
            return true;
        }

        return false;
    }

    template<typename T>
    constexpr inline bool erase_from_sorted_vector(std::vector<T>& vector, const T& value) {
        auto it = std::lower_bound(vector.begin(), vector.end(), value);

        if (it != vector.end() && *it == value) {
            vector.insert(it, value);
            return true;
        }

        return false;
    }
} // namespace crow_middlewares_detail

namespace remote_ip_guard_detail {
    using namespace crow_middlewares_detail;

    template<const char* ip_list, const bool whitelist, const bool frozen_ips, std::enable_if_t<is_valid_ips(ip_list, !frozen_ips), bool> = true>
    class RemoteIpGuard {
        using self_t = RemoteIpGuard;

        using current_ip_set_t = std::conditional_t<frozen_ips, const std::vector<int32_t>, std::vector<int32_t>>;
        current_ip_set_t ip_set = parse_ip_list_template_arg();

        using current_frozen_t = std::conditional_t<frozen_ips, empty_type, bool>;
        [[no_unique_address]] current_frozen_t frozen = current_frozen_t();

        constexpr std::string ip_list_type_str() const noexcept {
            if constexpr (whitelist) {
                return "whitelist";
            } else {
                return "blacklis";
            }
        }

        constexpr std::string ip_list_type_action_str() const noexcept {
            if constexpr (whitelist) {
                return "allow";
            } else {
                return "block";
            }
        }

        constexpr std::string ip_list_type_negative_action_str() const noexcept {
            if constexpr (whitelist) {
                return "block";
            } else {
                return "allow";
            }
        }

    public:
        RemoteIpGuard() {
            if constexpr (!is_empty(ip_list)) {
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
            if constexpr (!frozen_ips) {
                // Modifications during runtime may invalidate iterators that are being used for allowing/denying requests
                if (!frozen) freeze();
            }
        }

    private:
        // Assumes that the ip_list string is in a valid format, in other words, it's been validated using the is_valid_ips function
        constexpr std::vector<int32_t> parse_ip_list_template_arg() {
            if (is_empty(ip_list)) return {};

            std::vector<int32_t> _ip_set;

            const char* aip = ip_list;

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
                        insert_into_sorted_vector(_ip_set, ipv4);

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
            insert_into_sorted_vector(_ip_set, ipv4);

            _ip_set.shrink_to_fit();

            return _ip_set;
        }

        std::string get_ip_list_str() const noexcept {
            if (ip_set.size() == 0) return "";

            const size_t ip_max_size = 15;

            std::string str;
            str.reserve((ip_max_size + 2 /* accounting for the comma+space separation */) * ip_set.size());

            auto it = ip_set.begin();
            for (size_t i = ip_set.size(); i > 1; i--) {
                str.append(int_to_ipv4_string(*it));
                str.append(", ");
                ++it;
            }
            str.append(int_to_ipv4_string(*it));

            return str;
        }

        std::string get_ip_list_str(const std::vector<std::string>& ips) const noexcept {
            if (ips.size() == 0) return "";

            const size_t ip_max_size = 15;

            std::string str;
            str.reserve((ip_max_size + 2 /* accounting for the comma+space separation */) * ips.size());

            auto it = ips.begin();
            for (size_t i = ips.size(); i > 1; i--) {
                str.append(*it);
                str.append(", ");
                ++it;
            }
            str.append(*it);

            return str;
        }

        inline void log_ip_list_already_frozen() const noexcept {
            CROW_LOG_WARNING << "IP " << ip_list_type_str() << " is already frozen";
        }

        inline void log_ip_is_not_valid(const std::string ip) const noexcept {
            CROW_LOG_WARNING << "IP '" << ip << "' is not valid";
        }
    public:
        inline bool is_ip_allowed(const std::string ip) const noexcept {
            int32_t ipv4 = 0;
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                log_ip_is_not_valid(ip);
                return false;
            }

            const bool ip_set_contains = std::binary_search(ip_set.begin(), ip_set.end(), ipv4);

            if constexpr (whitelist) {
                return ip_set_contains;
            } else {
                return !ip_set_contains;
            }
        }

        inline bool is_ip_forbidden(const std::string ip) const noexcept {
            return !is_ip_allowed(ip);
        }

        template<const bool _frozen_ips = frozen_ips>
        typename std::enable_if<!_frozen_ips, self_t&>::type add_ip(const std::string ip) {
            assert(!frozen && is_valid_ip(ip.c_str()));

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            int32_t ipv4 = 0;
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                log_ip_is_not_valid(ip);
                return *this;
            }

            CROW_LOG_INFO << "Adding IP to the " << ip_list_type_str() << ": " << ip;

            insert_into_sorted_vector(ip_set, ipv4);

            return *this;
        }

        template<const bool _frozen_ips = frozen_ips>
        typename std::enable_if<!_frozen_ips, self_t&>::type add_ips(const std::vector<std::string>& ips) {
            assert(!frozen);

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            if (ips.size() == 0) return *this;

            std::vector<int32_t> parsed;
            parsed.reserve(ips.size());
            for (auto it = ips.begin(); it != ips.end(); ++it) {
                int32_t ipv4 = 0;
                if (inet_pton(AF_INET, it->c_str(), &ipv4) != 1) {
                    log_ip_is_not_valid(*it);
                    return *this;
                }

                parsed.push_back(ipv4);
            }
            std::sort(parsed.begin(), parsed.end());
            parsed.erase(std::unique(parsed.begin(), parsed.end()), parsed.end());

            CROW_LOG_INFO << "Adding IPs to the " << ip_list_type_str() << ": " << get_ip_list_str(ips);

            if (ip_set.size() == 0) {
                // Swap ip_set with the temporary vector containing unique parsed sorted input ips

                ip_set.swap(parsed);
            } else {
                // Merge the temporary vector containing unique parsed sorted input ips and ip_set into another temporary vector while skipping duplicates and then swap that container with ip_set

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

        template<const bool _frozen_ips = frozen_ips>
        typename std::enable_if<!_frozen_ips, self_t&>::type remove_ip(const std::string ip) {
            assert(!frozen && is_valid_ip(ip.c_str()));

            if (frozen) {
                log_ip_list_already_frozen();
                return *this;
            }

            int32_t ipv4 = 0;
            if (inet_pton(AF_INET, ip.c_str(), &ipv4) != 1) {
                log_ip_is_not_valid(ip);
                return *this;
            }

            CROW_LOG_INFO << "Removing IP from the " << ip_list_type_str() << ": " << ip;

            erase_from_sorted_vector(ip_set, ipv4);

            return *this;
        }

        template<const bool _frozen_ips = frozen_ips>
        typename std::enable_if<!_frozen_ips, self_t&>::type clear_ips() {
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

        template<const bool _frozen_ips = frozen_ips>
        typename std::enable_if<!_frozen_ips, bool>::type is_frozen() {
            return frozen;
        }

        template<const bool _frozen_ips = frozen_ips>
        typename std::enable_if<!_frozen_ips, self_t&>::type freeze() {
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
    template<const char* allowed_ip_list>
    using WhitelistIpGuard = remote_ip_guard_detail::RemoteIpGuard<allowed_ip_list, true, true>;

    /*template<const char* allowed_ip_list>
    using DynamicWhitelistIpGuard = remote_ip_guard_detail::RemoteIpGuard<allowed_ip_list, true, false>;*/

    using DynamicWhitelistIpGuard = remote_ip_guard_detail::RemoteIpGuard<nullptr, true, false>;

    template<const char* forbidden_ip_list>
    using BlacklistIpGuard = remote_ip_guard_detail::RemoteIpGuard<forbidden_ip_list, false, true>;

    /*template<const char* forbidden_ip_list>
    using DynamicBlacklistIpGuard = remote_ip_guard_detail::RemoteIpGuard<forbidden_ip_list, false, false>;*/

    using DynamicBlacklistIpGuard = remote_ip_guard_detail::RemoteIpGuard<nullptr, false, false>;
} // namespace crow
