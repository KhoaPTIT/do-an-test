# Luật vs ML trên harness Phase 3 (TỰ SINH bởi `python -m verification.rule_ml_experiment` — đừng sửa tay)

Model `isolation_forest` v3-870bee225d73-03b95613-s42 (ngưỡng 0.5905), commit `a4d62ef55bfcd5867a0b77b46d4dc29f2f4b68aa`.

Kịch bản tấn công: 420 · A (cả hai) 86 · B (chỉ luật) 314 · **C (chỉ ML) 10** · D (không bên nào) 10 · ML có thể chấm 120/420.

Lưu lượng bình thường: 5647 lần thử, ML chấm 4551, ML gắn cờ (báo nhầm) 59 (1.30% lần được chấm), luật gắn cờ 0.

| Hành vi | Kịch bản | Luật? | ML? | ML trong phạm vi? | Điểm ML (max) | Detector chính | Quyết định cuối | Nhóm |
|---|---|---|---|---|---|---|---|---|
| username_enumeration | 12 tên không tồn tại, cách 43s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 13 tên không tồn tại, cách 37s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 11 tên không tồn tại, cách 57s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 13 tên không tồn tại, cách 42s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 9 tên không tồn tại, cách 62s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 8 tên không tồn tại, cách 47s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 10 tên không tồn tại, cách 38s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 9 tên không tồn tại, cách 58s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 12 tên không tồn tại, cách 44s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 9 tên không tồn tại, cách 42s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 11 tên không tồn tại, cách 38s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 13 tên không tồn tại, cách 48s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 11 tên không tồn tại, cách 38s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 12 tên không tồn tại, cách 53s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 13 tên không tồn tại, cách 47s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 13 tên không tồn tại, cách 49s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 13 tên không tồn tại, cách 41s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 9 tên không tồn tại, cách 45s, UA=kịch bản | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 10 tên không tồn tại, cách 52s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| username_enumeration | 8 tên không tồn tại, cách 55s, UA=trình duyệt | có | không | không |  | username_enumeration | allow + alert | B |
| password_spray_slow | 19 tài khoản (27 lần sai), cách 30 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 19 tài khoản (19 lần sai), cách 48 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 19 tài khoản (28 lần sai), cách 25 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 23 tài khoản (23 lần sai), cách 20 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 24 tài khoản (24 lần sai), cách 12 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 22 tài khoản (22 lần sai), cách 30 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 23 tài khoản (32 lần sai), cách 35 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 19 tài khoản (24 lần sai), cách 11 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 20 tài khoản (20 lần sai), cách 32 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 22 tài khoản (22 lần sai), cách 47 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 20 tài khoản (20 lần sai), cách 35 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 21 tài khoản (21 lần sai), cách 42 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 19 tài khoản (19 lần sai), cách 28 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 24 tài khoản (24 lần sai), cách 51 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 23 tài khoản (23 lần sai), cách 18 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 22 tài khoản (22 lần sai), cách 52 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 18 tài khoản (18 lần sai), cách 50 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 24 tài khoản (24 lần sai), cách 32 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 22 tài khoản (33 lần sai), cách 26 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| password_spray_slow | 16 tài khoản (24 lần sai), cách 24 phút | có | không | không |  | password_spray_slow | allow + alert | B |
| distributed_bruteforce | 13 lần sai từ 5 IP cùng khu vực, cách 93s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 13 lần sai từ 8 IP cùng khu vực, cách 25s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 9 lần sai từ 9 IP cùng khu vực, cách 17s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 9 lần sai từ 7 IP cùng khu vực, cách 22s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 8 lần sai từ 5 IP cùng khu vực, cách 196s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 8 lần sai từ 6 IP cùng khu vực, cách 246s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 11 lần sai từ 7 IP cùng khu vực, cách 160s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 12 lần sai từ 11 IP cùng khu vực, cách 127s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 9 lần sai từ 5 IP cùng khu vực, cách 180s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 12 lần sai từ 6 IP cùng khu vực, cách 123s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 13 lần sai từ 12 IP cùng khu vực, cách 25s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 10 lần sai từ 10 IP cùng khu vực, cách 37s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 13 lần sai từ 8 IP cùng khu vực, cách 23s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 11 lần sai từ 9 IP cùng khu vực, cách 245s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 10 lần sai từ 8 IP cùng khu vực, cách 150s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 9 lần sai từ 7 IP cùng khu vực, cách 20s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 13 lần sai từ 9 IP cùng khu vực, cách 234s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 8 lần sai từ 8 IP cùng khu vực, cách 224s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 9 lần sai từ 8 IP cùng khu vực, cách 85s | có | không | không |  | distributed_bruteforce | allow + alert | B |
| distributed_bruteforce | 9 lần sai từ 6 IP cùng khu vực, cách 39s (nhanh: brute_force cũng khớp) | có | không | không |  | distributed_bruteforce | allow + alert | B |
| success_after_failures | 5 lần sai cách 53s rồi đúng sau 7s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 8 lần sai cách 41s rồi đúng sau 54s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 9 lần sai cách 15s rồi đúng sau 19s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 6 lần sai cách 76s rồi đúng sau 52s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 9 lần sai cách 22s rồi đúng sau 38s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 8 lần sai cách 18s rồi đúng sau 57s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 7 lần sai cách 49s rồi đúng sau 51s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 8 lần sai cách 20s rồi đúng sau 56s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 5 lần sai cách 77s rồi đúng sau 10s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 8 lần sai cách 21s rồi đúng sau 22s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 7 lần sai cách 56s rồi đúng sau 21s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 6 lần sai cách 75s rồi đúng sau 8s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 8 lần sai cách 14s rồi đúng sau 25s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 9 lần sai cách 31s rồi đúng sau 46s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 6 lần sai cách 17s rồi đúng sau 54s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 6 lần sai cách 50s rồi đúng sau 41s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 7 lần sai cách 28s rồi đúng sau 7s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 8 lần sai cách 13s rồi đúng sau 44s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 9 lần sai cách 23s rồi đúng sau 19s | có | không | không |  | success_after_failures | allow + alert | B |
| success_after_failures | 9 lần sai cách 25s rồi đúng sau 46s | có | không | không |  | success_after_failures | allow + alert | B |
| dormant_account_login | ngủ đông 386 ngày, đổi both | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 273 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 326 ngày, đổi country | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 362 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 179 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 281 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 234 ngày, đổi device | có | có | có | 0.7165 | dormant_account_login | alert | A |
| dormant_account_login | ngủ đông 397 ngày, đổi both | có | có | có | 0.7804 | dormant_account_login | alert | A |
| dormant_account_login | ngủ đông 261 ngày, đổi device | có | có | có | 0.7299 | dormant_account_login | alert | A |
| dormant_account_login | ngủ đông 302 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 315 ngày, đổi country | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 354 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 305 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 144 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 231 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 378 ngày, đổi country | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 255 ngày, đổi country | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 148 ngày, đổi device | có | không | không |  | dormant_account_login | allow + alert | B |
| dormant_account_login | ngủ đông 374 ngày, đổi country | có | có | có | 0.762 | dormant_account_login | alert | A |
| dormant_account_login | ngủ đông 220 ngày, đổi device | có | có | có | 0.6971 | dormant_account_login | alert | A |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.21) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.6) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | tên không tồn tại qua Tor (198.51.100.14) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.39) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.30) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | tên không tồn tại qua Tor (198.51.100.33) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.31) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.13) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | tên không tồn tại qua Tor (198.51.100.23) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.15) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.23) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | tên không tồn tại qua Tor (198.51.100.12) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.11) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.33) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | tên không tồn tại qua Tor (198.51.100.3) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.30) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.13) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | tên không tồn tại qua Tor (198.51.100.4) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | đăng nhập thành công qua Tor (198.51.100.25) | có | không | không |  | tor_exit | allow + alert | B |
| tor_exit | thử sai một lần qua Tor (198.51.100.19) | có | không | không |  | tor_exit | allow + alert | B |
| brute_force | 11 lần sai cách 58s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 7 lần sai cách 11s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 5 lần sai cách 6s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 9 lần sai cách 4s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 10 lần sai cách 41s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 10 lần sai cách 19s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 7 lần sai cách 8s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 8 lần sai cách 23s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 8 lần sai cách 17s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 5 lần sai cách 18s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 5 lần sai cách 16s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 5 lần sai cách 54s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 8 lần sai cách 17s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 11 lần sai cách 31s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 8 lần sai cách 65s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 10 lần sai cách 55s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 12 lần sai cách 46s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 12 lần sai cách 46s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 11 lần sai cách 29s | có | không | không |  | brute_force | allow + alert | B |
| brute_force | 12 lần sai cách 67s | có | không | không |  | brute_force | allow + alert | B |
| credential_stuffing | 16 lần sai / 5 tài khoản không tồn tại, cách 15s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 11 lần sai / 6 tài khoản có thật, cách 6s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 10 lần sai / 7 tài khoản có thật, cách 13s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 10 lần sai / 7 tài khoản có thật, cách 16s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 18 lần sai / 7 tài khoản có thật, cách 7s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 12 lần sai / 12 tài khoản có thật, cách 15s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 11 lần sai / 11 tài khoản có thật, cách 25s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 16 lần sai / 12 tài khoản có thật, cách 5s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 15 lần sai / 12 tài khoản không tồn tại, cách 15s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 15 lần sai / 9 tài khoản không tồn tại, cách 15s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 18 lần sai / 12 tài khoản có thật, cách 9s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 19 lần sai / 5 tài khoản có thật, cách 11s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 13 lần sai / 10 tài khoản có thật, cách 12s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 13 lần sai / 7 tài khoản có thật, cách 23s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 12 lần sai / 10 tài khoản không tồn tại, cách 22s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 15 lần sai / 10 tài khoản có thật, cách 3s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 18 lần sai / 6 tài khoản có thật, cách 6s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 19 lần sai / 12 tài khoản không tồn tại, cách 5s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 14 lần sai / 11 tài khoản có thật, cách 20s | có | không | không |  | credential_stuffing | allow + alert | B |
| credential_stuffing | 11 lần sai / 7 tài khoản có thật, cách 9s | có | không | không |  | credential_stuffing | allow + alert | B |
| blocklist_hit | chặn ip=203.0.113.214 | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn cidr=203.0.113.64/26 | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn asn=64533 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn username=victim (có hạn) | có | không | không |  | blocklist_hit | lock + alert | B |
| blocklist_hit | chặn ip=198.51.100.249 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn cidr=198.51.100.192/26 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn asn=64532 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn username=victim | có | không | không |  | blocklist_hit | lock + alert | B |
| blocklist_hit | chặn ip=198.51.100.235 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn cidr=198.51.100.192/26 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn asn=64530 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn username=victim | có | không | không |  | blocklist_hit | lock + alert | B |
| blocklist_hit | chặn ip=203.0.113.189 | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn cidr=203.0.113.128/26 | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn asn=64533 | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn username=victim (có hạn) | có | không | không |  | blocklist_hit | lock + alert | B |
| blocklist_hit | chặn ip=203.0.113.167 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn cidr=203.0.113.128/26 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn asn=64530 (có hạn) | có | không | không |  | blocklist_hit | lock (blocklist) + alert | B |
| blocklist_hit | chặn username=victim | có | không | không |  | blocklist_hit | lock + alert | B |
| impossible_travel | 17175km trong 953 phút (~1,081 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 9197km trong 98 phút (~5,643 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 3661km trong 65 phút (~3,374 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 12316km trong 468 phút (~1,577 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 12316km trong 341 phút (~2,168 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 13150km trong 264 phút (~2,987 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 13150km trong 492 phút (~1,603 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 9197km trong 224 phút (~2,459 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 3661km trong 208 phút (~1,057 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 9197km trong 58 phút (~9,575 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 3661km trong 58 phút (~3,767 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 9197km trong 273 phút (~2,023 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 3661km trong 105 phút (~2,088 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 17175km trong 677 phút (~1,521 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 12316km trong 252 phút (~2,931 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 17175km trong 198 phút (~5,212 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 9197km trong 212 phút (~2,597 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 9197km trong 224 phút (~2,468 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 12316km trong 122 phút (~6,040 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| impossible_travel | 12316km trong 45 phút (~16,313 km/h) | có | không | không |  | impossible_travel | allow + alert | B |
| country_hop | 4 lần sai từ 3 quốc gia (VN, US, FR), cách 4.8h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 4 quốc gia (VN, FR, BR, JP), cách 2.9h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 6 lần sai từ 4 quốc gia (US, DE, JP, VN), cách 1.9h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 4 lần sai từ 3 quốc gia (JP, FR, BR), cách 1.7h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 8 lần sai từ 5 quốc gia (US, JP, VN, FR, DE), cách 1.3h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 5 quốc gia (BR, DE, JP, VN, US), cách 3.5h | có | không | không |  | country_hop, scripted_client | allow + alert | B |
| country_hop | 6 lần sai từ 4 quốc gia (BR, DE, JP, FR), cách 1.7h | có | không | không |  | country_hop, scripted_client | allow + alert | B |
| country_hop | 5 lần sai từ 3 quốc gia (VN, DE, US), cách 1.3h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 6 lần sai từ 4 quốc gia (JP, VN, US, BR), cách 2.0h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 4 quốc gia (BR, VN, JP, US), cách 0.6h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 5 quốc gia (BR, FR, JP, VN, DE), cách 3.1h | có | không | không |  | country_hop, scripted_client | allow + alert | B |
| country_hop | 8 lần sai từ 5 quốc gia (BR, JP, DE, FR, US), cách 2.4h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 5 quốc gia (BR, DE, JP, VN, US), cách 3.2h | có | không | không |  | country_hop, scripted_client | allow + alert | B |
| country_hop | 6 lần sai từ 4 quốc gia (US, VN, JP, BR), cách 4.5h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 8 lần sai từ 5 quốc gia (VN, FR, US, BR, JP), cách 0.5h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 6 lần sai từ 4 quốc gia (JP, BR, VN, US), cách 3.1h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 4 quốc gia (VN, BR, FR, US), cách 1.6h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 8 lần sai từ 5 quốc gia (FR, JP, DE, VN, BR), cách 2.8h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 5 lần sai từ 4 quốc gia (BR, VN, DE, JP), cách 0.7h | có | không | không |  | country_hop | allow + alert | B |
| country_hop | 7 lần sai từ 5 quốc gia (US, JP, BR, FR, DE), cách 0.5h | có | không | không |  | country_hop | allow + alert | B |
| ua_rotation | 11 lần sai, 5 họ UA, 4 tài khoản, cách 79s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 10 lần sai, 8 họ UA, 4 tài khoản, cách 81s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 10 lần sai, 7 họ UA, 3 tài khoản, cách 81s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 11 lần sai, 8 họ UA, 3 tài khoản, cách 84s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 12 lần sai, 6 họ UA, 4 tài khoản, cách 85s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 9 lần sai, 6 họ UA, 2 tài khoản, cách 45s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 9 lần sai, 5 họ UA, 4 tài khoản, cách 79s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 8 lần sai, 5 họ UA, 1 tài khoản (không tồn tại), cách 79s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 11 lần sai, 8 họ UA, 2 tài khoản (không tồn tại), cách 64s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 12 lần sai, 7 họ UA, 4 tài khoản (không tồn tại), cách 85s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 11 lần sai, 7 họ UA, 2 tài khoản, cách 57s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 11 lần sai, 6 họ UA, 4 tài khoản, cách 81s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 12 lần sai, 6 họ UA, 1 tài khoản, cách 83s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 10 lần sai, 6 họ UA, 1 tài khoản, cách 78s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 12 lần sai, 8 họ UA, 2 tài khoản (không tồn tại), cách 77s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 12 lần sai, 7 họ UA, 2 tài khoản, cách 82s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 12 lần sai, 5 họ UA, 1 tài khoản, cách 85s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 8 lần sai, 7 họ UA, 2 tài khoản, cách 58s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 8 lần sai, 7 họ UA, 2 tài khoản, cách 78s | có | không | không |  | ua_rotation | allow + alert | B |
| ua_rotation | 9 lần sai, 7 họ UA, 4 tài khoản (không tồn tại), cách 83s | có | không | không |  | ua_rotation | allow + alert | B |
| scripted_client | tên không tồn tại, python-requests/2.31.0 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, curl/8.7.1 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, Wget/1.21.4 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | đăng nhập thành công bằng HTTPie/3.2.2 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | đăng nhập thành công bằng Go-http-client/1.1 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | đăng nhập thành công bằng python-httpx/0.27.0 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 2 lần thử sai bằng Python/3.11 aiohttp/3.9.3 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 3 lần thử sai bằng libwww-perl/6.72 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 1 lần thử sai bằng Java/17.0.9 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, Apache-HttpClient/4.5.14 (Java/17.0.9) | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 3 lần thử sai bằng python-requests/2.31.0 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 3 lần thử sai bằng curl/8.7.1 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 3 lần thử sai bằng Wget/1.21.4 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | 3 lần thử sai bằng HTTPie/3.2.2 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | đăng nhập thành công bằng Go-http-client/1.1 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | đăng nhập thành công bằng python-httpx/0.27.0 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, Python/3.11 aiohttp/3.9.3 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, libwww-perl/6.72 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, Java/17.0.9 | có | không | không |  | scripted_client | allow + alert | B |
| scripted_client | tên không tồn tại, Apache-HttpClient/4.5.14 (Java/17.0.9) | có | không | không |  | scripted_client | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Googl) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; bingb) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (DuckDuckBot/1.1; (+http://duck) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | 3 yêu cầu đăng nhập từ crawler (Mozilla/5.0 (compatible; Yande) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Ahref) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (facebookexternalhit/1.1 (+http) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | 3 yêu cầu đăng nhập từ crawler (Mozilla/5.0 (compatible; Baidu) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Semru) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | 1 yêu cầu đăng nhập từ crawler (Mozilla/5.0 (compatible; MJ12b) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (Linux; Android 6.) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Googl) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; bingb) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (DuckDuckBot/1.1; (+http://duck) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Yande) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Ahref) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (facebookexternalhit/1.1 (+http) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | crawler thử tên không tồn tại (Mozilla/5.0 (compatible; Baidu) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | 1 yêu cầu đăng nhập từ crawler (Mozilla/5.0 (compatible; Semru) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | 1 yêu cầu đăng nhập từ crawler (Mozilla/5.0 (compatible; MJ12b) | có | không | không |  | bot_user_agent | allow + alert | B |
| bot_user_agent | 3 yêu cầu đăng nhập từ crawler (Mozilla/5.0 (Linux; Android 6.) | có | không | không |  | bot_user_agent | allow + alert | B |
| unusual_device | hồ sơ 22 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.6504 | unusual_device | alert | A |
| unusual_device | hồ sơ 23 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.6529 | unusual_device | alert | A |
| unusual_device | hồ sơ 32 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.5982 | unusual_device | alert | A |
| unusual_device | hồ sơ 37 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.6997 | unusual_device | alert | A |
| unusual_device | hồ sơ 15 ngày, 3 thiết bị quen → thiết bị mới | có | có | có | 0.7896 | unusual_device | alert | A |
| unusual_device | hồ sơ 22 ngày, 3 thiết bị quen → thiết bị mới | có | có | có | 0.7688 | unusual_device | alert | A |
| unusual_device | hồ sơ 24 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.606 | unusual_device | alert | A |
| unusual_device | hồ sơ 34 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.7885 | unusual_device | alert | A |
| unusual_device | hồ sơ 29 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.6529 | unusual_device | alert | A |
| unusual_device | hồ sơ 36 ngày, 3 thiết bị quen → thiết bị mới | có | không | có | 0.59 | unusual_device | allow + alert | B |
| unusual_device | hồ sơ 39 ngày, 2 thiết bị quen → thiết bị mới | có | có | có | 0.769 | unusual_device | alert | A |
| unusual_device | hồ sơ 32 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.6556 | unusual_device | alert | A |
| unusual_device | hồ sơ 22 ngày, 2 thiết bị quen → thiết bị mới | có | có | có | 0.7777 | unusual_device | alert | A |
| unusual_device | hồ sơ 19 ngày, 3 thiết bị quen → thiết bị mới | có | có | có | 0.7675 | unusual_device | alert | A |
| unusual_device | hồ sơ 28 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.6485 | unusual_device | alert | A |
| unusual_device | hồ sơ 10 ngày, 2 thiết bị quen → thiết bị mới | có | có | có | 0.7846 | unusual_device | alert | A |
| unusual_device | hồ sơ 38 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.791 | unusual_device | alert | A |
| unusual_device | hồ sơ 17 ngày, 1 thiết bị quen → thiết bị mới | có | có | có | 0.7571 | unusual_device | alert | A |
| unusual_device | hồ sơ 39 ngày, 2 thiết bị quen → thiết bị mới | có | có | có | 0.7894 | unusual_device | alert | A |
| unusual_device | hồ sơ 13 ngày, 3 thiết bị quen → thiết bị mới | có | có | có | 0.6048 | unusual_device | alert | A |
| unusual_location | hồ sơ VN 31 ngày → lần đầu ở FR | có | có | có | 0.7664 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 40 ngày → lần đầu ở US | có | có | có | 0.7608 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 32 ngày (+từng đến JP) → lần đầu ở FR | có | có | có | 0.7749 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 35 ngày (+từng đến BR) → lần đầu ở JP | có | có | có | 0.7387 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 25 ngày → lần đầu ở US | có | có | có | 0.77 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 39 ngày → lần đầu ở US | có | có | có | 0.7743 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 19 ngày (+từng đến DE) → lần đầu ở US | có | có | có | 0.744 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 37 ngày → lần đầu ở FR | có | có | có | 0.7836 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 18 ngày (+từng đến US) → lần đầu ở BR | có | có | có | 0.7456 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 30 ngày → lần đầu ở DE | có | có | có | 0.7522 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 18 ngày → lần đầu ở FR | có | có | có | 0.7752 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 14 ngày (+từng đến FR) → lần đầu ở JP | có | có | có | 0.763 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 37 ngày (+từng đến DE) → lần đầu ở BR | có | có | có | 0.7491 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 23 ngày → lần đầu ở US | có | có | có | 0.7682 | impossible_travel | alert | A |
| unusual_location | hồ sơ VN 39 ngày → lần đầu ở JP | có | có | có | 0.7735 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 30 ngày (+từng đến DE) → lần đầu ở US | có | có | có | 0.7657 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 20 ngày → lần đầu ở FR | có | có | có | 0.7641 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 33 ngày → lần đầu ở DE | có | có | có | 0.7798 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 32 ngày → lần đầu ở FR | có | có | có | 0.7743 | unusual_location | alert | A |
| unusual_location | hồ sơ VN 20 ngày (+từng đến FR) → lần đầu ở US | có | có | có | 0.7719 | unusual_location | alert | A |
| unusual_hour | quen 7.0h±1.8h (12 ngày) → đăng nhập 20.0h | không | có | có | 0.5948 | unusual_hour | alert | C |
| unusual_hour | quen 4.4h±1.1h (16 ngày) → đăng nhập 14.6h | không | không | có | 0.5858 |  | allow | D |
| unusual_hour | quen 3.6h±1.5h (14 ngày) → đăng nhập 15.5h | không | có | có | 0.604 | unusual_hour | alert | C |
| unusual_hour | quen 19.1h±2.9h (28 ngày) → đăng nhập 6.3h | không | có | có | 0.6016 | unusual_hour | alert | C |
| unusual_hour | quen 7.2h±1.8h (19 ngày) → đăng nhập 18.9h | không | có | có | 0.6039 | unusual_hour | alert | C |
| unusual_hour | quen 2.3h±0.6h (28 ngày) → đăng nhập 17.1h | không | không | có | 0.5757 |  | allow | D |
| unusual_hour | quen 9.9h±2.3h (28 ngày) → đăng nhập 0.0h | không | không | có | 0.5831 |  | allow | D |
| unusual_hour | quen 1.6h±1.5h (14 ngày) → đăng nhập 15.3h | không | không | có | 0.5839 |  | allow | D |
| unusual_hour | quen 6.7h±3.1h (37 ngày) → đăng nhập 20.7h | không | không | có | 0.5817 |  | allow | D |
| unusual_hour | quen 10.7h±3.6h (19 ngày) → đăng nhập 0.1h | không | có | có | 0.5916 | unusual_hour | alert | C |
| unusual_hour | quen 16.0h±2.1h (23 ngày) → đăng nhập 6.9h | không | không | có | 0.5747 |  | allow | D |
| unusual_hour | quen 1.7h±2.2h (35 ngày) → đăng nhập 13.3h | không | không | có | 0.5807 |  | allow | D |
| unusual_hour | quen 6.1h±3.8h (37 ngày) → đăng nhập 20.0h | không | có | có | 0.5948 | unusual_hour | alert | C |
| unusual_hour | quen 15.0h±1.2h (20 ngày) → đăng nhập 5.4h | không | không | có | 0.5817 |  | allow | D |
| unusual_hour | quen 15.4h±2.5h (19 ngày) → đăng nhập 1.1h | không | không | có | 0.5724 |  | allow | D |
| unusual_hour | quen 13.2h±3.7h (33 ngày) → đăng nhập 23.9h | không | có | có | 0.5932 | unusual_hour | alert | C |
| unusual_hour | quen 18.8h±1.3h (30 ngày) → đăng nhập 9.3h | không | không | có | 0.5455 |  | allow | D |
| unusual_hour | quen 3.8h±3.8h (18 ngày) → đăng nhập 16.0h | không | có | có | 0.604 | unusual_hour | alert | C |
| unusual_hour | quen 16.2h±1.7h (36 ngày) → đăng nhập 2.8h | không | có | có | 0.5928 | unusual_hour | alert | C |
| unusual_hour | quen 14.5h±3.8h (36 ngày) → đăng nhập 4.2h | không | có | có | 0.5908 | unusual_hour | alert | C |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (20 ngày) → 10 lần thành công cách 53s | có | có | có | 0.7818 | impossible_travel | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (27 ngày) → 11 lần thành công cách 37s | có | có | có | 0.7738 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (30 ngày) → 12 lần thành công cách 15s | có | có | có | 0.5983 | login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (13 ngày) → 9 lần thành công cách 48s | có | không | có | 0.5593 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (30 ngày) → 9 lần thành công cách 49s | có | có | có | 0.5958 | login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (35 ngày) → 12 lần thành công cách 43s | có | có | có | 0.7729 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (38 ngày) → 12 lần thành công cách 24s | có | có | có | 0.7467 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (21 ngày) → 14 lần thành công cách 42s | có | có | có | 0.7605 | login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (35 ngày) → 11 lần thành công cách 34s | có | không | có | 0.5601 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (18 ngày) → 15 lần thành công cách 40s | có | không | có | 0.5346 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (36 ngày) → 12 lần thành công cách 40s | có | không | có | 0.5617 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (11 ngày) → 12 lần thành công cách 24s | có | có | có | 0.774 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (11 ngày) → 14 lần thành công cách 23s | có | có | có | 0.7759 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (13 ngày) → 15 lần thành công cách 35s | có | không | có | 0.5313 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (34 ngày) → 10 lần thành công cách 25s | có | có | có | 0.7909 | login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (16 ngày) → 10 lần thành công cách 60s | có | không | có | 0.5726 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (28 ngày) → 10 lần thành công cách 63s | có | không | có | 0.5694 | login_velocity_spike | allow + alert | B |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (18 ngày) → 10 lần thành công cách 47s | có | có | có | 0.756 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (36 ngày) → 12 lần thành công cách 17s | có | có | có | 0.7234 | hybrid_ml, login_velocity_spike | alert | A |
| login_velocity_spike | hồ sơ 1–3 lần/ngày (30 ngày) → 9 lần thành công cách 13s | có | có | có | 0.7559 | hybrid_ml, login_velocity_spike | alert | A |
| regular_rhythm | 12 lần sai cách đều ~2.8s (±0%), 3 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~15.5s (±4%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 11 lần sai cách đều ~4.9s (±12%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 12 lần sai cách đều ~23.5s (±8%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 11 lần sai cách đều ~6.2s (±2%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 11 lần sai cách đều ~18.1s (±4%), 3 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~18.9s (±1%), 3 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 12 lần sai cách đều ~18.3s (±7%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 12 lần sai cách đều ~7.7s (±7%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~21.4s (±4%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~18.8s (±11%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~16.1s (±10%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 14 lần sai cách đều ~14.3s (±6%), 4 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~9.9s (±5%), 3 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~15.1s (±7%), 3 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 11 lần sai cách đều ~14.8s (±4%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~12.9s (±11%), 3 tài khoản | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 10 lần sai cách đều ~8.5s (±9%), 3 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 12 lần sai cách đều ~19.9s (±2%), 4 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| regular_rhythm | 16 lần sai cách đều ~10.0s (±12%), 4 tài khoản (không tồn tại) | có | không | không |  | regular_rhythm | allow + alert | B |
| rare_network_login | JP dân cư (64530), nền 1328 lượt, ASN chưa ai dùng | có | có | có | 0.7274 | rare_network_login | alert | A |
| rare_network_login | US dân cư (64523), nền 1222 lượt, ASN chưa ai dùng | có | có | có | 0.7541 | rare_network_login | alert | A |
| rare_network_login | US dân cư (64523), nền 925 lượt, ASN chưa ai dùng | có | có | có | 0.7431 | rare_network_login | alert | A |
| rare_network_login | NL datacenter (64521), nền 573 lượt, ASN chiếm ~0.4% | có | có | có | 0.7376 | rare_network_login | alert | A |
| rare_network_login | SG VPN (64522), nền 967 lượt, ASN chưa ai dùng | có | có | có | 0.7152 | rare_network_login | alert | A |
| rare_network_login | VN Đà Nẵng (ASN 64515, cùng quốc gia), nền 2356 lượt, ASN chưa ai dùng | có | có | có | 0.6974 | rare_network_login | alert | A |
| rare_network_login | JP dân cư (64530), nền 1295 lượt, ASN chưa ai dùng | có | có | có | 0.76 | rare_network_login | alert | A |
| rare_network_login | NL datacenter (64521), nền 1958 lượt, ASN chiếm ~0.6% | có | có | có | 0.7519 | rare_network_login | alert | A |
| rare_network_login | SG VPN (64522), nền 1607 lượt, ASN chưa ai dùng | có | có | có | 0.7187 | rare_network_login | alert | A |
| rare_network_login | FR dân cư (64531), nền 1821 lượt, ASN chưa ai dùng | có | có | có | 0.7526 | rare_network_login | alert | A |
| rare_network_login | US dân cư (64523), nền 2082 lượt, ASN chưa ai dùng | có | có | có | 0.761 | rare_network_login | alert | A |
| rare_network_login | US dân cư (64523), nền 2259 lượt, ASN chiếm ~0.5% | có | có | có | 0.7596 | rare_network_login | alert | A |
| rare_network_login | FR dân cư (64531), nền 857 lượt, ASN chưa ai dùng | có | có | có | 0.7427 | rare_network_login | alert | A |
| rare_network_login | NL datacenter (64521), nền 880 lượt, ASN chưa ai dùng | có | có | có | 0.744 | rare_network_login | alert | A |
| rare_network_login | BR dân cư (64532), nền 735 lượt, ASN chưa ai dùng | có | có | có | 0.7573 | rare_network_login | alert | A |
| rare_network_login | FR dân cư (64531), nền 1457 lượt, ASN chiếm ~0.5% | có | có | có | 0.753 | rare_network_login | alert | A |
| rare_network_login | US dân cư (64523), nền 1947 lượt, ASN chưa ai dùng | có | có | có | 0.7603 | rare_network_login | alert | A |
| rare_network_login | NL datacenter (64521), nền 1026 lượt, ASN chưa ai dùng | có | có | có | 0.7442 | rare_network_login | alert | A |
| rare_network_login | JP dân cư (64530), nền 2127 lượt, ASN chưa ai dùng | có | có | có | 0.727 | rare_network_login | alert | A |
| rare_network_login | VN Đà Nẵng (ASN 64515, cùng quốc gia), nền 1998 lượt, ASN chiếm ~0.5% | có | có | có | 0.6772 | rare_network_login | alert | A |
| multi_context_simultaneous | nhà VN (có toạ độ) → nước khác (chỉ quốc gia), cách 469s | có | không | không |  | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | VN (chỉ quốc gia) → nước khác (có toạ độ), cách 264s | có | có | có | 0.7737 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nước khác (chỉ quốc gia) → chủ ở nhà VN, cách 330s | có | không | có | 0.516 | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | VN → SG (cả hai chỉ quốc gia), cách 234s | có | không | không |  | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | nhà VN (có toạ độ) → nước khác (chỉ quốc gia) + quốc gia thứ ba, cách 225s | có | không | có | 0.5872 | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | VN (chỉ quốc gia) → nước khác (có toạ độ) + quốc gia thứ ba, cách 239s | có | có | có | 0.7648 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nước khác (chỉ quốc gia) → chủ ở nhà VN, cách 223s | có | không | không |  | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | VN → SG (cả hai chỉ quốc gia) + quốc gia thứ ba, cách 490s | có | có | có | 0.591 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nhà VN (có toạ độ) → nước khác (chỉ quốc gia), cách 137s | có | có | có | 0.6955 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | VN (chỉ quốc gia) → nước khác (có toạ độ), cách 95s | có | có | có | 0.7484 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nước khác (chỉ quốc gia) → chủ ở nhà VN, cách 546s | có | không | có | 0.516 | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | SG → KR (cả hai chỉ quốc gia), cách 173s | có | có | có | 0.6964 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nhà VN (có toạ độ) → nước khác (chỉ quốc gia), cách 276s | có | không | không |  | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | VN (chỉ quốc gia) → nước khác (có toạ độ), cách 209s | có | có | có | 0.7744 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nước khác (chỉ quốc gia) → chủ ở nhà VN, cách 271s | có | có | có | 0.6268 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | US → KR (cả hai chỉ quốc gia), cách 558s | có | không | không |  | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | nhà VN (có toạ độ) → nước khác (chỉ quốc gia), cách 559s | có | không | có | 0.539 | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | VN (chỉ quốc gia) → nước khác (có toạ độ), cách 585s | có | có | có | 0.7635 | multi_context_simultaneous | alert | A |
| multi_context_simultaneous | nước khác (chỉ quốc gia) → chủ ở nhà VN, cách 346s | có | không | có | 0.516 | multi_context_simultaneous | allow + alert | B |
| multi_context_simultaneous | SG → VN (cả hai chỉ quốc gia), cách 143s | có | không | có | 0.5706 | multi_context_simultaneous | allow + alert | B |
