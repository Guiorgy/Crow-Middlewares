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

#include <cassert>

namespace {
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
        constexpr empty_type(T _) {}

        template<typename T1, typename T2>
        constexpr empty_type(T1 _, T2 __) {}

        template<typename T1, typename T2, typename T3>
        constexpr empty_type(T1 _, T2 __, T2 ___) {}
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

    constexpr bool is_valid_ips(const char* ips, const bool can_be_list = true) noexcept {
        if (is_empty(ips)) return true;

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
                    if (dots != 3 || subnet_len == 0) return false;

                    subnet[subnet_len] = '\0';
                    if (!is_valid_subnet(subnet)) return false;

                    subnet_len = 0;
                    dots = 0;
                    ip_len = 0;

                    break;
                case '.':
                    if (dots == 3) return false;

                    subnet[subnet_len] = '\0';
                    if (!is_valid_subnet(subnet)) return false;

                    subnet_len = 0;
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
        return is_valid_ips(ip, false);
    }
} // namespace

namespace crow {
    template<const char* allowed_ips, std::enable_if_t<is_valid_ips(allowed_ips), bool> = true>
    class RemoteIpGuard {
        using self_t = RemoteIpGuard;

        std::set<std::string> allowed_ip_set;

        using current_frozen_t = std::conditional_t<is_empty(allowed_ips), bool, empty_type>;
        [[no_unique_address]] current_frozen_t frozen = current_frozen_t();

    public:
        RemoteIpGuard() {
            parse_allowed_ips_template_arg();

            if (allowed_ip_set.size() != 0) {
                CROW_LOG_DEBUG << "Allowed IPs: " << get_allowed_ips_list();
            }
        }

        struct context {};

        void before_handle(crow::request& req, crow::response& res, context& ctx) const {
            if (!is_ip_allowed(req.remote_ip_address)) {
                CROW_LOG_DEBUG << "Unauthorized access attempt from IP " << req.remote_ip_address << ": [" << method_strings[(unsigned char)req.method] << "] " << req.url << " [Result: 403 Forbidden]";

                res.code = crow::status::FORBIDDEN;
                res.end();
            }
        }

        void after_handle(crow::request& req, crow::response& res, context& ctx) const {}

    private:
        // Assumes that the allowed_ips string is in a valid format, in other words, it's been validated using the is_valid_ips function
        void parse_allowed_ips_template_arg() {
            assert(allowed_ip_set.size() == 0);

            if (is_empty(allowed_ips)) return;

            const char* aip = allowed_ips;

            char ip_buffer[16] = {0};
            int ip_len = 0;

            int subnet_len = 0;
            int dots = 0;

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
                        allowed_ip_set.emplace(std::string(ip_buffer));

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
            allowed_ip_set.emplace(std::string(ip_buffer));
        }

        std::string get_allowed_ips_list() const noexcept {
            const size_t ip_max_size = 15;

            std::string str;
            str.reserve((ip_max_size + 2 /* accounting for the comma+space separation */) * allowed_ip_set.size());

            std::set<std::string>::iterator it = allowed_ip_set.begin();
            for (size_t i = allowed_ip_set.size(); i > 1; i--) {
                str.append(*it);
                str.append(", ");
                ++it;
            }
            str.append(*it);

            return str;
        }
    public:
        inline bool is_ip_allowed(std::string ip) const noexcept {
            return allowed_ip_set.find(ip) != allowed_ip_set.end();
        }

        template<const char* _allowed_ips = allowed_ips>
        typename std::enable_if<is_empty(_allowed_ips), self_t&>::type add_ip(const std::string ip) {
            assert(!frozen && is_valid_ip(ip.c_str()));

            if (frozen) {
                CROW_LOG_WARNING << "Allowed IP list is already frozen";
                return *this;
            }
            if (!is_valid_ip(ip.c_str())) {
                CROW_LOG_WARNING << "IP '" << ip << "' is not valid";
                return *this;
            }

            CROW_LOG_DEBUG << "Adding allowed IP: " << ip;

            allowed_ip_set.emplace(ip);

            return *this;
        }

        template<const char* _allowed_ips = allowed_ips>
        typename std::enable_if<is_empty(_allowed_ips), self_t&>::type remove_ip(const std::string ip) {
            assert(!frozen && is_valid_ip(ip.c_str()));

            if (frozen) {
                CROW_LOG_WARNING << "Allowed IP list is already frozen";
                return *this;
            }
            if (!is_valid_ip(ip.c_str())) {
                CROW_LOG_WARNING << "IP '" << ip << "' is not valid";
                return *this;
            }

            CROW_LOG_DEBUG << "Removing allowed IP: " << ip;

            allowed_ip_set.erase(ip);

            return *this;
        }

        template<const char* _allowed_ips = allowed_ips>
        typename std::enable_if<is_empty(_allowed_ips), self_t&>::type freeze() {
            assert(!frozen);

            if (frozen) {
                CROW_LOG_WARNING << "Allowed IP list is already frozen";
                return *this;
            }

            CROW_LOG_DEBUG << "Freezing " << allowed_ip_set.size() << " allowed IPs: " << get_allowed_ips_list();

            frozen = true;

            return *this;
        }

        template<const char* _allowed_ips = allowed_ips>
        typename std::enable_if<is_empty(_allowed_ips), bool>::type is_frozen() {
            return frozen;
        }
    };

    using DynamicIpGuard = RemoteIpGuard<nullptr>;
} // namespace crow
