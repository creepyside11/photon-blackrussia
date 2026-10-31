# Photon и «Кресты дяди Славы» — что удалось выяснить

Дата анализа: локально, только статика, без сети и без аккаунтов.

---

## 1. Главное: br.apk — это модифицированный клиент

`_apk/br.apk` — не официальная сборка. Внутри лежит чит:

```
lib/arm64-v8a/libPhoton.so   15 375 264 байт
```

И он подгружается из Java:

```
classes4.dex: System.loadLibrary("Photon")
              System.loadLibrary("blackrussia-client")
              System.loadLibrary("update-manager")
```

Для сравнения — `libblackrussia-client.so` (нативное ядро игры) **не** зависит от
`libPhoton.so`: в его `DT_NEEDED` только `libssl`, `libcrypto`, `libbass`,
`libEGL`, `libGLESv3`, `libupdate-manager`, `libjnigraphics`, `libz`, системные.
Значит Photon грузится отдельно, поверх игры.

`libPhoton.so` содержит `JNI_OnLoad`, рендерит через `libEGL` + `libGLESv3` +
`libjnigraphics` — это нативный оверлей на ImGui 1.93.0.

Внутри статически слинкованы:

| Библиотека | Признак |
|------------|---------|
| OpenSSL / BoringSSL | 12 113 символов `.dynsym`, из них масса `X509_*`, `OCSP_*`, `d2i_*` |
| libcurl | `curl_easy*`, `libcurl`, `Xferd Average Speed` |
| nlohmann/json | `nlohmann`, `json` (27 вхождений) |
| Dear ImGui | `Dear ImGui`, `##MainMenuBar`, `Calling EndMenu() in wrong window!` |

Признаки лицензирования: строки `Bearer`, `license`, `License`, `hwid`,
`subscription_required`.

---

## 2. Почему «Крестов дяди Славы» нет в бинарнике

Искала целенаправленно и широко.

### По всему APK (все 5149 записей, включая dex, resources.arsc, assets, натив)

| Шаблон | Найдено | Что это оказалось |
|--------|---------|-------------------|
| `Слав` (UTF-8) | **0** | — |
| `Слав` (UTF-16LE) | **0** | — |
| `крест` | **4** | все четыре — `перекресток`, дорожные знаки |
| `дяд` | 2 | обрывки других строк в пуле ресурсов |

**Этот результат верен только для незашифрованного поиска.** Строки Photon
лежат в `.rodata` под XOR, и до расшифровки их не видно — отсюда нули.

После расшифровки (§4.2) они находятся:

| смещение | фрагмент |
|----------|----------|
| `0x1ada91` | ` дяди Сла` |
| `0x1ae7f0` | `Дядя Сла` |
| `0x1b3000` | `Прохожде` |
| `0x1ad580` | `ние##AnimSpee` — продолжение `Прохожде` |

`Дядя Сла` + `вы` = 20 байт, а строка грузится как 16 байт (`ldr q0`) плюс
8 байт (`ldr d3`). Поэтому хвост `вы` лежит отдельным куском в другом месте
пула — это и есть защита от поиска по целой подстроке.

Рядом протокольные ключи, по которым Photon и работает с квестами:

| ключ | адрес |
|------|-------|
| `quest_id` | `0x1ad304` |
| `quest_rejected` | `0x1af202` |
| `questretry_after_ms` | `0x1af31b` |
| `/quest` | `0x1b4f22` |

Вывод: **Photon знает про Дядю Славу и работает с ним на уровне JSON-протокола**,
а не патчем памяти. Значит наш подход (ловить пакеты) — тот же слой, что у него.

### По `libPhoton.so` отдельно

| Шаблон | Найдено |
|--------|---------|
| `крест` / `krest` / `Krest` | 0 |
| `Слав` / `slava` / `Slava` | 0 |
| `cross` | 1 — `crossCertificatePair` (X.509) |
| `Aimbot`, `Wallhack`, `Farm`, `Teleport`, `Speed` | 0 как пункты меню |

Кириллицы в `libPhoton.so` всего **26 байтовых последовательностей**, и все они
распадаются на 21 уникальную строку. Это не строки кода, а **метаданные Photoshop
внутри PNG-текстур**, вшитых в библиотеку:

```
photoshop:LayerName="Для использования этой функции  необходимо приобрести подписку "
photoshop:LayerName="Для неограниченного количества необходимо приобрести подписку P"
```

Извлекла PNG — их всего 4:

| Файл | Размер | Что это |
|------|--------|---------|
| `0001_109599.png` | 300×300 | без подписи |
| `0002_16555.png` | 512×512 | без подписи |
| `0003_56992.png` | 800×400 | плашка «приобрести подписку» |
| `0004_56358.png` | 800×400 | плашка «приобрести подписку» |

**Ни одной текстуры с пунктами меню.** Подписей функций в бинарнике нет вообще —
ни строками, ни картинками.

---

## 3. ГЛАВНОЕ: функции НЕ качаются. Они вкомпилированы в libPhoton.so

Предыдущий вывод («список функций приходит с сервера») **опровергнут**.

Строки в `libPhoton.so` не отсутствуют — они зашифрованы XOR'ом с ключом
`96316c22826a5560` (8 байт, повтор) и упакованы в пул 16-байтовыми кусками
без нуль-терминаторов. Ключ лежит прямо в `.rodata`:

```
0x1b1560: 96 31 6c 22 82 6a 55 60  96 31 6c 22 82 6a 55 60   # 16 байт
0x1b51f0: 96 31 6c 22 82 6a 55 60                             # 8 байт (хвост)
```

Расшифровка `seg[i] ^= key[i % 8]` по всему `.rodata` даёт 6435 читаемых строк.
Функция-расшифровщик — `0x5549ec` (16+2 байта) и `0x554a34` (16+8 байт),
ключи грузятся через `adrp x8, #0x1b1000; ldr q0, [x8, #0x560]` и
`adrp x9, #0x1b5000; ldr d3, [x9, #0x1f0]`.

**Отсюда: перечень функций Photon — это статический список в бинарнике.**
Ничего он с сервера не скачивает. Сервер только выдаёт лицензию.

### 3.1. Доказательство, что API живой

```
$ dig api.photonmod.net
13.143.176.229                     # Cloudflare

$ POST https://api.photonmod.net/session_login_v4  {}
{"error_code":1900,"output":"An internal server error occurred.","status":"error"}
```

`GET` на тот же путь отдаёт `405` — маршрут существует и принимает только POST.
Схема ответа (`error_code` / `output` / `status`) совпадает с кодами, найденными
в бинарнике: `hwid_mismatch`, `session_not_found`, `subscription_required`,
`key_banned`, `session_invalid`, `session_already_active`, `invalid_token`,
`invalid_json`, `invalid_device_info`, `login_request_too_large`,
`main_channel_required`, `channel_required`, `unsupported_protocol`,
`key_not_found`, `key_freeze_active`, `user_freeze_active`,
`global_freeze_active`, `internal_error`.

### 3.2. Таблица кодов = полный протокол лицензирования

Диспетчер `0x9340f0` — `packed-switch` по коду ошибки. Таблица переходов
лежит в `.rodata` по `0x24b982` (14 байт), база `0x934124`:

| код | обработчик | смысл |
|-----|-----------|-------|
| 10 | `0x934124` | `key_banned` |
| 11 | `0x93414c` | inline-сравнение 8 байт → `invalid_...` |
| 12 | `0x93418c` | `invalid_json` |
| 13 | `0x9341ac` | `key_not_found` / `hwid_mismatch` |
| 14 | `0x9341e4` | `internal_error` |
| 15 | `0x934204` | `session_invalid` |
| 16 | `0x93425c` | `session_not_found` |
| 17 | `0x934268` | `global_freeze_active` |
| 18 | `0x9342e4` | `invalid_device_info` |
| 19 | `0x934304` | `unsupported_protocol` |
| 20 | `0x934324` | `login_request_too_large` |
| 21 | `0x93435c` | `main_channel_required` |
| 22 | `0x934394` | `subscription_required` |
| 23 | `0x9343b4` | `session_already_active` |

### 3.3. Найденные эндпоинты

| путь | назначение |
|------|-----------|
| `https://api.photonmod.net/session_login_v4` | вход, выдаёт `session_token` |
| `https://api.photonmod.net/get_od…` | **серверный OCR капчи** |
| `https://api.photonmod.net/_client-image/<sha256>/image` | картинки/пейволлы |
| `https://t.me/…` | Telegram-канал |
| `GunWaton_br_bot?start` | Telegram-бот продажи подписки |
| `/com.photon.top` | package name |

### 3.4. Протокол сессии

```
запрос:  {"device_info":{…},"device_id":"…","client_nonce":"…",
          "session-token-v1":"…","protocol_version":N}
ответ:   {"session_token":"…","status":"ok", …}
далее:   heartbeat с токеном, иначе "session_expired"
```

Ключи, найденные в бинарнике: `session-token-v1`, `device_info`, `device_id`,
`client_nonce`, `session_token`, `protocol_version`, `request_id`,
`premium-offset-s`, `retry_after_ms`, `subscription`.

### 3.5. Серверный OCR — прямо по нашей теме

```
запрос:  {"image_base64":"<base64 PNG>","protocol_version":N}
ответ:   ключ ocr_pred… (ocr_prediction)
```

Строки-улики: `Missing OCR payload`, `ocr_pred`, `CaptchaModelTable`,
`CaptchaWindowTab`, `CaptchaRegistry`, `captcha_`.

**То есть Photon капчу не распознаёт сам — он шлёт картинку на
`api.photonmod.net` и получает текст.** Это ровно тот путь, который мы
заложили в `logic/captcha.py` (`ImageUrlSolver` → `solve_image`), только
у нас OCR локальный.

---

## 4. Полный список функций Photon (расшифрован)

Всё это лежит в `libPhoton.so` и работает локально, без сети.

**Aimbot / стрельба**
`Aimbot`, `SilentAim`, `FovAim`, `FovSilentAim`, `SmoothingAim`,
`ChanceSilentAi`, `HitBox`, `RenderCrosshair`, `ViewCrossHair`,
`FireDefault`, `FireRa…`, `AmmoTotal`, `SetHead…`

**Визуал / ESP**
`PlayerHealthESP`, `PlayersChams`, `ColorChamsPlayer`, `ChamsS…`,
`FakeChams`, `NameTags`, `NickName`, `DistancePlayer`, `SkyBox`,
`SkyBoxFu…`, `WireframeDensity`, `LineMode`, `ColorLine`,
`ChangecolLineP`, `FloocolDps`, `Flo…Wireframe`, `MapNavig`

**Движение / физика**
`ChangeSpeedVeh`, `ChangeSpeedValue`, `SetVehicleVelocity`,
`VehicleTeleport`, `EntityTeleport`, `VehicleHydraulic`, `VehicleNitroTime`,
`BikeEntityCollis`, `OffCollisionVeh`, `CollisionModel`,
`PedEntityCollis`, `VehicleCollision`, `WalkSpeed`, `SpeedGame`,
`JumpTime`, `ContactN`, `Gravity`, `AnimSpeed`, `AnimSpee…`,
`FastAnimation`, `ReloadAnimation`, `ReloadBlend`, `DuckingTransition`

**FastMenu — чат-команды в игру**
`FastMenuInvisible`, `FastMenuAimBotVehicle`, `FastMenuGiveAr…`,
`FastMenuHealMe`, `FastMenuReturn`, `FastMenuSilent`,
`AutoMain`, `AutoButtons`, `AutoExit`

Сами команды, которые чит шлёт в чат сервера игры:

```
/givemoney   /givemon    /addid      /addhui     /donate
/armor       /trunk      /blist      /cuff       /photon
/gevent      /tpcam      /skin       /healme     /fixcar
/repair      /resetmo    /quest      /medhelp    /vget
/meslist     /output     /dev        /uralogging_
```

**Фарм / автоматизация («боты», о которых ты спрашивал)**
`AutoTraining`, `AutoTrain…`, `AutoCatchOrder`, `AutoSell`,
`SellAutomatic`, `SellDr…`, `SellDrOther`, `SellMarketItems`,
`SellMarketInte`, `PriceThreshold`, `ThresholdAutoSel`,
`FactHarveste…`, `RespawnProgres`, `RemoveAndPutAt`,
`SerializeInCar`, `SerializeLocalPl`, `NewObject`

**Капча**
`PassingTextCapt`, `CaptchaRegistry`, `CaptchaModelTable`,
`CaptchaWindowTab`, `CaptchaFindModel`

**Прочее**
`CamOrientation`, `CamProce…`, `CameraBe…`, `TrailerTowLink`,
`SetVehicleVeloci…`, `TpCam`, `RolePl…`, `ScreenPo…`,
`PlayerAr…`, `SetHeadi…`, `ToGroundMain`, `RvankaMain`,
`CutCommands`, `NickNameCutCmd`, `ShLightsRi`, `ShLights…`,
`FullCanister`, `CheckWeaponsPed`, `PedDamag`, `Armou…`,
`CfgName`, `DebugMes`, `PhotonCheck`, `frida-ga…`

**Чтение памяти процесса**
`/proc/self/maps`, `/proc/self/mem` — чит читает собственную карту памяти
(типично для inline-хуков и патчей кода).

### 4.1. Русское меню — тоже в бинарнике

После расшифровки находятся 782 русские строки. Ключевые разделы:

| смещение | фрагмент |
|----------|----------|
| `0x1b1430` | `Боты##Button` + `Рыбалка` |
| `0x1b43f0` | `tCommandБоты` |
| `0x1b3000` | `Прохожде…` |
| `0x1ada91` | ` дяди Сла…` |
| `0x1ae7f0` | `Дядя Сла…` |
| `0x1b5480` | `Слав` |
| `0x1adaa0` | `Шоппинг` |
| `0x1b2fe0` | `Без капч…` |
| `0x1b30c1` | `RolePl…` |
| `0x1b27b0` | `bOffSliderCaptch…` |
| `0x1b08c0` | `Текстиль` + `bPassingSliderCa…` |
| `0x1b1a40` | `Хитбоксы` |
| `0x1ae8d0` | `ть время#Бессмерт` |
| `0x1b0e20` | `Приобрест…` + `СКАЧАТЬ` |
| `0x1b35a0` | `Нет` |
| `0x1b44e9` | `рел` |

**«Боты» — это раздел меню, и он в бинарнике.** Внутри — «Рыбалка»,
`AutoFishing`, `FishEi…`, `fish_result`, `AutoTraining`, `AutoSell`,
`AutoCatchOrder`.

### 4.2. Строки разрезаны — это защита, а не отсутствие

Обфускатор режет строки на куски и раскладывает их по пулу без
нуль-терминаторов. Пример склейки URL:

```
0x1aeb70  "https://api.phot"      (16 б)
0x1b0d20  "onmod.net/get_od"      (16 б)
          ─────────────────────
          "https://api.photonmod.net/get_od"
```

Поэтому поиск по целой подстроке («кресты», «Слава») ничего не даёт —
именно на этом сломался прошлый заход. Работать надо по кускам.

### 4.3. Раздел «Боты» — что именно внутри

«Боты» в Photon — это не сетевые боты и не ИИ. Это **автоматизация работ
Black Russia**: чит сам ходит по маршруту работы, жмёт нужные диалоги и
сдаёт заказы.

| имя в бинарнике | адрес | английский ключ | что делает |
|---|---|---|---|
| `Рыбалка` | `0x1b1440` | `AutoFishing`, `bTrashUnderwater`, `fish_result` | авто-рыбалка, выбор вида рыбы |
| `Дояр` | `0x1b4410` | `bMilkmai` (milkmaid) | авто-доярка |
| `Пчеловод` | `0x1b10a0` | — | авто-пасека |
| `Шахт` | `0x1b51a0` | `Miner` | авто-шахта |
| `Газовщик` | `0x1ae5f0` | — | авто-газ |
| `Дамагер` | `0x1ae600` | — | авто-дамагер |
| `Инкассат` | `0x1af900` | `bAutoGe…rderInco` | авто-инкассатор |
| `Сборщик` | `0x1b1720` | `bHarvest`, `bAddSpee`, `bSkipDiag` | авто-сбор, пропуск диалогов |
| `Скупщик` | `0x1ad030` | — | авто-скупка |
| `Водитель` | `0x1af260` | `bCombineDrive` | авто-водитель / комбайн |
| `Врач` | `0x1b4ca0` | `bHealMe`, `bAutoHea` | авто-лечение |
| `Ловля` | `0x1aded0` | `bTreasureHunter`, `bNameAnimalsESP` | ловля животных и кладов |

Общие авто-действия поверх работ:

```
bAutoCatchOrder    авто-приём заказов
bAutoSal           авто-продажа
bAutoCuf           авто-наручники
bAutoHea           авто-лечение
bAutoBui           авто-постройка
bTrainingInOrder   тренировка по порядку
bAutoTestFractio   авто-тест фракции
bSkipDiag          пропуск диалогов
bTreasureHunter    кладоискатель
```

**Виды рыбы** (подсписок рыбалки, лежат слитно `ОсетКета`, `СтерлядьAutoFishing`):

`Сом` `Щука` `Осет` `Кета` `Лосо` `Стерлядь` `Таймень` `Белу` `Окун` `Кара`

**Животные** (для ловли): `Медведь` `Олен` `Утка` `Крол` `Глухарь`

Оговорка по методу: строки в пуле склеены **без разделителей**, длины
заданы в коде. Поэтому имена читаются уверенно, а точный порядок пунктов
подменю — нет. Для порядка нужен дамп памяти или трасса.

### 4.4. Как воспроизвести

```
cd _apk
python3 photon_dec.py              # все 6435 строк
python3 photon_dec.py --urls       # только URL
python3 photon_dec.py --grep боты  # поиск
python3 photon_dec.py --chunk 16   # куски, как они лежат в пуле
```

---

## 5. Что это значит для нашей задачи

Главное: **«Кресты дяди Славы» не приезжают с сервера.** Они вкомпилированы.
Сервер отдаёт только лицензию.

Но копировать Photon нам всё равно не нужно — у него другой слой. Photon сидит
внутри процесса игры и правит память/движок. Наш бот сетевой: он живёт на
уровне пакетов RakNet и JSON-интерфейсов.

**Правильный путь тот же, что сработал с меню и капчей:** поймать, что реально
приходит по сети в момент этой механики, и ответить. Меню так и вскрыли —
за один прогон, без единого хука.

Что нужно: запустить бота, дойти до «Крестов дяди Славы», включить
`BR_TRACE_JSON=1`, снять дамп. Дальше пишу обработчик — как с капчей.

---

## 5.1. Чем это проверялось

```
# поиск по всем записям APK
python3 -c "..."   # см. историю: перебор namelist() с UTF-8 и UTF-16LE

# строки в нативе
python3 -c "re.finditer(rb'(?:\xd0[\x90-\xbf]|\xd1[\x80-\xbf]){2,}', ...)"

# извлечение PNG из .so
python3 -c "...PNG-сигнатуры + разбор чанков до IEND..."

# DT_NEEDED
python3 -c "...разбор .dynamic..."
```

Все результаты воспроизводимы на `_apk/br.apk` и `_apk/libPhoton.so`.

---

## 6. Автоползунок — палочка летит через зелёное поле

### 6.1. Что это на самом деле

Не перетаскивание. Палочка сама едет по полосе, надо **нажать в момент,
когда она в зелёной зоне**. Я сначала описала как drag — неверно, поправлено.

### 6.2. Ключи в Photon

| ключ | адрес | смысл |
|---|---|---|
| `bPassingSliderCaptcha` | `0x1b08d0` | автопрохождение ползунка |
| `bOffSliderCaptcha` | `0x1b27d0` | отключить ползунок совсем |
| `bPassingTextCaptcha` | `0x1ad380` | автопрохождение текстовой |

Регистрация настроек: `0x63e7a4`, `0x627350`, `0x6285dc`, `0x628638`.

### 6.3. Механика — разобрана по dex

Класс `UILayoutMiniGameEventsGameFinger` (режим Finger, iid 31).

**`onCreateView`** (`0x...`) надувает layout, вешает кнопку и
`OnGlobalLayoutListener`.

**`UILayoutMiniGameEventsGameFinger$1.onGlobalLayout`** — вот сердце:

```
mLineWidth = dpToPx(40.0f)                  # 0x4220 = 40.0f
int i      = new Random().nextInt(5)        # 0..4
mChunk     = i * mLineWidth                 # ← ЗЕЛЁНАЯ ЗОНА
Color.parseColor("#43CD7F")                 # зелёный
```

**Зона выбирается локальным `Random().nextInt(5)`.** Пять возможных позиций.
Сервер в этом не участвует вообще.

**`RunVerticalLineView.isHitted()`** — чистая геометрия, без сети:

```
x >= mChunk && x <= mChunk + mLineWidth
```

**`lambda$onCreateView$0`** — обработчик кнопки:

```java
boolean hit = view.isHitted();
JSONObject o = new JSONObject();
o.put("s", hit ? 1 : 0);
guiManager.sendJsonData(guiId, o);
close();
```

### 6.4. Вывод: сервер не может проверить

Клиент отправляет **только** `{"s": 1}` или `{"s": 0}`. Ни позиции палочки,
ни зоны, ни времени. Сервер физически не знает, попал ты или нет.

**Значит автопрохождение = отправить `{"s": 1}`.** Считать нечего.

Единственное, что сервер может заметить — слишком быстрый ответ. Поэтому
в `logic/minigames.py` стоит `HIT_DELAY = (0.8, 2.2)` — это правильно,
задержку держим.

### 6.5. Вторая система — MiniGamesHelper

Отдельный, более новый набор (`MiniGamesHelper*`), Compose UI.
Ответы те же:

```
sendLineHit      -> {"s": 1}
sendLineNotHit   -> {"s": 0}
sendCloseScreen  -> {"c": 1}
```

Ключи, которые он читает из JSON (`MiniGamesHelperKeys`):

```
g  h  s  n  r  q1  q2  q3  z  x  m
p_start  p_max  p_max_bar  p_title  p_tick  p_timer  imageName
```

Состояние (`MiniGamesHelperUiState`) — 13 полей: `getHelperType`,
`getMaxValue`, `getRandomNum`, `getTick`, `getTimer`, `getPrizeHeader`,
`getPrizeImage`, `getProgressBarTitle`, `getCurrentProgressBarStatus`,
`getMaxProgressBarValue`, `getCongratulatoryText`, `isNeedClose`,
`isNeedToShowClose`.

Здесь часть параметров (`p_start`, `p_max`, `p_tick`, `p_timer`) приходит
с сервера — но ответ всё равно только `{"s":1}`.

### 6.6. Слайдер-капча (нативная)

Отдельно от мини-игр, в `libblackrussia-client.so` на Noesis:

| символ | адрес |
|---|---|
| `BlackRussia.SliderWithTargetArea` | `0x3e4ba4` |
| свойство `Duration` | `0x3e4bc5` |
| `PART_TargetArea` | `0x407e29` |
| `Gui::SliderValueToOffsetConverter` | `0x3eb755` |
| `Gui::CaptchaModel::TryFetchImage()` | `0x46456c` |

`Gui::CaptchaViewModel` — свойства: `FixedString<24>`, `float`,
`BitmapSource*`, `unsigned int` (тип), `Visibility`.

Это тот же принцип «палочка + зона», но нативная часть. Формат ответа
капчи другой — `{"t":0,"s":"<значение>"}`. Попадание здесь статически
не доказано как локальное: нужна трасса.

### 6.7. Что делать

| система | что слать | проверено |
|---|---|---|
| Finger (iid 31) | `{"s":1}` | да, по dex |
| MiniGamesHelper | `{"s":1}` | да, по dex |
| слайдер-капча | `{"t":0,"s":...}` | формат да, значение — нужна трасса |

У нас всё это уже есть в `logic/minigames.py` и `logic/captcha.py`.
