<div align="center">

# 🔬 Photon / Black Russia — разобранный клиент

<p align="center">
  <b>Содержимое Android-приложения, разложенное по файлам. Сам APK не выложен — только его потроха.</b>
</p>

<a href="https://t.me/raknetbrnews1">
  <img src="https://img.shields.io/badge/📢_Telegram_Канал-@raknetbrnews1-0088cc?style=for-the-badge&logo=telegram&logoColor=white" alt="Наш Telegram Канал"/>
</a>
<a href="https://github.com/creepyside11/black">
  <img src="https://img.shields.io/badge/🤖_Открытый_RakCRMP-Клиент_для_Black_Russia-black?style=for-the-badge&logo=github&logoColor=white" alt="Открытый RakCRMP"/>
</a>
<a href="https://blackrussia.online/">
  <img src="https://img.shields.io/badge/🌐_Black_Russia-blackrussia.online-E0584B?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Официальный сайт"/>
</a>

</div>

---

## 📢 Наш канал и открытый проект

Все свежие новости, патчи протокола, разборы клиентов и обходы античитов — в нашем Telegram-канале.
👉 **[@raknetbrnews1](https://t.me/raknetbrnews1)** — подписывайся.

У нас есть **открытый RakCRMP** — клиент для Black Russia, который позволяет запускать ботов на серверах игры. Код лежит открыто:
👉 **[github.com/creepyside11/black](https://github.com/creepyside11/black)**

---

# Photon / Black Russia — разобранный клиент

Содержимое Android-приложения, разложенное по файлам. **Сам APK здесь нет** —
только его потроха: код, нативные библиотеки, ресурсы, манифест.

## Что это за сборка

| Поле | Значение |
|------|----------|
| Пакет | `com.photon.top` |
| versionCode | `2000` |
| versionName | `16.111.19050` |
| Класс приложения | `com.blackhub.bronline.launcher.App` |
| Главная активность | `com.blackhub.bronline.game.core.JNIActivity` |
| minSdk / targetSdk | 26 / 37 |

Пакет называется `com.photon.top`, но класс приложения и точка входа —
из Black Russia (`com.blackhub.bronline`). Это и есть ответ на вопрос
«что такое Photon»: **клиент Блек Раши, переупакованный под своим именем
пакета, с внедрённым оверлеем.** Игра внутри настоящая, чит лежит сверху.

## Источник

```
файл      RakCRMP_patched.apk
размер    106 523 187 байт
sha256    5f0c668af2c142f37b2a1c60b1af57064cdaff7dc385c514254593b72d26341f
```

Этот APK пересобран и подписан нашим инструментом (`apkbuild.py`, схема
подписи v2, без Java). Подпись — **штатный тестовый ключ AOSP**
(`CN=Android, O=Android, L=Mountain View`), он публично лежит в самом
Android и ничего не значит.

## Что внутри

```
AndroidManifest.xml          бинарный манифест, 510 узлов
classes.dex … classes7.dex   7 файлов Dalvik
lib/arm64-v8a/               14 нативных библиотек
res/                         4750 файлов ресурсов
resources.arsc               таблица ресурсов, 14 546 записей
assets/                      ресурсы игры
META-INF/                    подписи и манифесты
```

Крупнейшее:

| Файл | Размер |
|------|--------|
| `lib/arm64-v8a/libblackrussia-client.so` | 34.6 МБ — игровое ядро |
| `classes.dex` | 29.3 МБ |
| `lib/arm64-v8a/libPhoton.so` | 13.4 МБ — **сам чит** |
| `classes4.dex` | 12.6 МБ |

## Чит: `libPhoton.so`

Нативный оверлей поверх игры. Линкуется с `libEGL`, `libGLESv3`,
`libjnigraphics` — то есть рисует поверх экрана. Внутри статически
слинкованы **Dear ImGui 1.93.0**, **libcurl**, **OpenSSL/BoringSSL** и
**nlohmann/json**. Есть `JNI_OnLoad`, читает `/proc/self/maps` и
`/proc/self/mem` — типичный признак inline-хуков.

Функции (расшифровано, полный список — в разделе ниже): аимбот, ESP,
изменение скорости и гравитации, телепорт транспорта, автопродажа,
прохождение капчи, и семейство кнопок `auto_*` — автопокупка премиума,
яхты, уникального, груза, мото, эконома.

Лицензирование своё: `https://api.photonmod.net/session_login_v4`,
поля `session-token-v1`, `device_id`, `client_nonce`, `hwid`.
Подписка называется Premium.

## Что вырезано

**`res/drawable/auto_premium.png`** — кнопка «авто-премиум». Удалена из
дампа, потому что работает криво.

Честно о последствиях: это только иконка. Логика осталась в `classes.dex` —
номер ресурса `0x7f080654` встречается там ровно один раз. Ресурс не
упоминается ни в одном layout, только в коде. Поэтому если кто-то будет
собирать APK обратно, ему нужно либо вернуть файл, либо убрать и ссылку
из кода, иначе меню полезет за несуществующей картинкой.

Остальные шесть из семейства (`auto_econom`, `auto_gruz`, `auto_middle`,
`auto_moto`, `auto_unique`, `auto_yacht`) на месте.

## Шифрование строк

Строки `libPhoton.so` лежат в `.rodata` под XOR — в открытом виде их не
видно. Расшифровка и разбор:

```
photon_dec.py             скрипт расшифровки
photon_dec.bin            расшифрованный дамп
photon_strings_dec.txt    782 русские строки
photon_analysis.md        полный разбор: функции, протокол лицензий, эндпоинты
```

## Предупреждение

Это дамп **чужого платного чита** и модифицированного клиента игры. Он
выложен для разбора. Права на Photon принадлежат его авторам, права на
Black Russia — студии. Если придёт жалоба, пострадает аккаунт целиком, а
не этот репозиторий.
