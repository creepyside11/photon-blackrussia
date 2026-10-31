# «Кресты дяди Славы»: статический разбор Photon + Black Russia

Только статический анализ файлов. Сеть не использовалась, живые аккаунты не трогались,
боты не запускались. Существующие файлы проекта не изменялись.

---

## 0. Короткий вывод

1. **Строки «кресты» в клиенте нет вообще.** Ни в UTF-8, ни в UTF-16LE, ни в dex,
   ни в `resources.arsc`, ни в обоих нативных `.so`, ни в одном из 5149 файлов APK.
   Слово «Слава»/«слав» не встречается в APK **ни разу**.
2. **«Дядя Слава» — серверная сущность.** Имя НПС приходит с сервера в поле `n`
   JSON-интерфейса `63` (NPC dialog), текст квеста — в поле `mq` интерфейса `39`.
   В клиенте этих строк нет по определению, поэтому искать «кресты» по имени бесполезно.
3. **Зато найдена сама механика мини-игр.** Это `MiniGamesHelperWithJSON` с
   **`screenId = 31`** (подтверждено дизассемблером: `const/16 v2, #31` ->
   `iput ... .screenId`). Три режима: `SCREEN_FINGER`, `SCREEN_UNTIE`, `SCREEN_PRIZE`.
   Ответы клиента: `{"s":1}` / `{"s":0}` / `{"t":1}` / `{"c":1}`.
4. **В Photon меню на русском/английском статически не восстанавливается.** Своих строк
   чита в бинаре нет в открытом виде: `.rodata` на 95% состоит из статически
   слинкованных OpenSSL 3.x / libcurl / ImGui 1.93.0. Проверены UTF-8, UTF-16LE,
   однобайтовый XOR (все 255 ключей) и реверс — ничего.
5. **Реализуемо ли в Python:** да, но не через «повторить фичу Photon», а через
   протокол. Автопрохождение = отправить `{"s":1}` в `interface_id=31` в момент,
   когда сервер ждёт попадания. Для «крестов» нужно один раз снять живой пакет,
   чтобы понять, каким `g` сервер открывает эту стадию.

---

## 1. Что именно искали и где

### 1.1. Набор шаблонов

| Шаблон | UTF-8 | UTF-16LE |
|---|---|---|
| `крест` / `Крест` / `КРЕСТ` | да | да |
| `слав` / `Слав` / `СЛАВ` | да | да |
| `krest` / `Krest` / `KREST` | да | да |
| `slava` / `Slava` | да | да |
| `cross` / `Cross` / `Crosses` / `CROSS` | да | да |

Плюс производные: `перекрест`, `крестик`, `развяж`, `узел`, `ползун`, `зелён`,
`зелен`, `шкал`, `мини-игр`, `мини игр`, `наставник`, `туториал`.

### 1.2. Результаты по файлам

**`_apk/libPhoton.so`** (15 375 264 байт, ELF64 aarch64, 26 секций):

| Шаблон | Найдено | Что это на самом деле |
|---|---|---|
| `cross` | 1 совпадение @ `0x1fbc3f` | `crossCertificatePair` — строка OID из OpenSSL |
| `Cross` | 0 | — |
| `крест`, `krest`, `slav`, `слав` | 0 | — |

Единственная кириллица в `libPhoton.so` — 35 байтовых серий, из них осмысленных 4,
и все четыре — **XMP-метаданные PNG-картинок платного экрана**:

```
0x221103  ... photoshop:LayerText="Для использования этой функции  необходимо
          приобрести подписку  Premium!"
0x221190  (тот же PNG, второй вложенный xpacket)
0x22efa3  ... LayerText="Для неограниченного количества необходимо приобрести
          подписку Premium!"
0x22f031  (тот же PNG, второй вложенный xpacket)
```

Это картинки пейволла, зашитые в бинарь как PNG с Adobe XMP. К меню отношения не имеют,
но подтверждают: подписка Premium — реальный гейт чита.

**`_apk/libblackrussia-client.so`** (36 296 864 байт): 33 кириллические серии, из них
31 уникальная, все короткие и мусорные (`Строительная`, `компания`, `Департамент`,
`Крик`, `Семья`, `Действие`, `чат`, `Работа`, `Организация`). Ни «крест», ни «слав».

**7 dex-файлов APK** (86 МБ суммарно):

```
classes.dex   30 726 660
classes2.dex  11 851 084
classes3.dex  10 007 644
classes4.dex  13 217 788
classes5.dex   8 485 104
classes6.dex  10 142 856
classes7.dex   1 724 508
```

Сырой поиск по байтам не дал ни одного совпадения по кириллице. Проверил, что это не
артефакт кодировки: разобрал пул строк `classes.dex` через `string_ids` — **96 293
строки, из них 0 с кириллицей** (выборка 3010 строк по всей длине пула).

Причина понятна: приложение собрано по правилам Android — весь пользовательский текст
лежит в `resources.arsc`, а в dex только ссылки на `R.string.*`. Поэтому дальше смотрел
ресурсы.

**`resources.arsc`** (4 312 040 байт, 24 951 строка в глобальном пуле, 14 546 записей):

| # пула | Строка | Вердикт |
|---|---|---|
| 5358 | `Водитель, на дороге которого установлен этот знак двигается по главной дороге и не обязан пропускать транспортные средства. Действует 1 перекресток.` | дорожный знак |
| 5524 | `Данный знак показывает водителю, что он двигается по второстепенной дороге и имеет преимущество при движении по перекрестку` | дорожный знак |
| 5528 | `Данный знак показывает водителю, что он двигается по главной дороге и пользуется приоритетом проезда перекрестка.` | дорожный знак |
| 5553 | `Для выхода нажмите на крестик (Х).` | кнопка закрытия |

Больше вхождений «крест» нет. «слав»/«Слав» — **ноль**.

**Все 5149 записей APK** (полный проход `zipfile.read` по каждой):

```
крест  -> 1 файл: resources.arsc (те же 4 строки)
слав   -> 0 файлов
Слав   -> 0 файлов
```

### 1.3. Что это значит

«Кресты дяди Славы» — не идентификатор в клиенте. Это либо серверное название стадии
квеста, либо сленг игроков. Клиент про такое название не знает: он рендерит то, что
пришлёт сервер в `mq` (текст цели) и открывает ту GUI-панель, на которую укажет
`screenId`.

Косвенное подтверждение: в `resources.arsc` есть `Дядя Миша`, но нет «Дяди Славы».
Имена НПС в BR приходят с сервера — в проекте это видно по
`onNpcDialog(bot, name, text, model, buttons)` и парсеру `npc_dialog`, где `n` — имя.

---

## 2. Photon: что удалось установить статически

Хотя меню не восстановлено, профиль чита читается уверенно.

### 2.1. ELF-структура

```
.text            vaddr 0x0041db00  size 0x9bc394   (основной код)
.rodata          vaddr 0x001ad000  size 0x1ad62b
.data            vaddr 0x00e866d8  file 0x00e7e6d8  size 0x2aaf0
.data.rel.ro     vaddr 0x00df41a0  size 0x80990
.init_array      vaddr 0x00e74b40  size 0x2b0   (86 конструкторов)
.dynsym          12 113 символов, из них 11 742 определённых, 370 импортов
```

Энтропия `.rodata` = 7.676 — высокая, но это не шифрование, а плотные бинарные таблицы
криптографии (`ecp_nistz256_precomputed` 0x25000 байт по адресу `0x287000`,
`ecp_sm2p256_precomputed` 0x80000 байт по `0x2ad000`).

### 2.2. Точка входа и гейт

```
JNI_OnLoad = 0x449a64
```

Подтверждено двумя способами: записью в `.dynsym` и валидным прологом ARM64 по этому
адресу:

```
0x449a64: fd 7b ba a9   stp x29, x30, [sp, #-0x60]!
0x449a68: fc 6f 01 a9   stp x28, x27, [sp, #0x10]
0x449a6c: fa 67 02 a9   stp x26, x25, [sp, #0x20]
```

Адрес из брифа верный — это настоящая функция, а не середина инструкции.

### 2.3. Что за зависимости

| Признак | Адрес/свидетельство | Вывод |
|---|---|---|
| `Dear ImGui 1.93.0 WIP (19297)` | `0x1f133e` | overlay на ImGui 1.93.0 |
| `ImGui_ImplOpenGL3_CreateDeviceObjects` | `0x1e6162`, `0x1ff3ed` | бэкенд OpenGL3 |
| импорты `eglGetCurrentContext`, `eglGetProcAddress`, `eglQuerySurface` | `.dynsym` | рисует поверх чужого GL-контекста |
| ~60 импортов `glCreateShader`, `glDrawElements`, `glUniformMatrix4fv` … | `.dynsym` | собственный GL-рендер |
| `16InterceptRouting`, `25FunctionInlineHookRouting`, `14CodeBufferBase`, `N2zz5arm6414TurboAssemblerE` | `0x279b80`, `0x279ba9`, `0x279b93`, `0x279ba4` | **Dobby** — inline-хукинг |
| `N8nlohmann16json_abi_v3_11_36...` | `0x23cad4` | nlohmann::json 3.11.3 |
| `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | `0x27b264` | base64 (вероятно для HTTP-канала) |
| `OpenSSL 3.x` + `libcurl` строки | весь `.rodata` | HTTPS-клиент внутри |
| импорты `mmap`, `mprotect` | `.dynsym` | исполняемая память под трамплины |
| импорт `__system_property_get` | `.dynsym` | сбор отпечатка устройства (HWID) |
| импорт `connect`, `dlopen`, `dlsym`, `fopen`, `fwrite` | `.dynsym` | сеть, поздний резолв, файлы конфига |

**Встроенные шрифты** (в `.data`, начало `0xe86ea0`): таблицы `cmap`, `glyf`, `head`,
`hhea`, `hmtx`, `loca`, `maxp`, `name`, `post` двух TTF:

```
Manrope-Bold        ("1.000;SHMI;Manrope-Bold")
icomoon             ("Font generated by IcoMoon.")
```

Manrope — с полной кириллицей. То есть меню **должно** уметь русский, но сами строки
в файле отсутствуют.

### 2.4. Почему меню не восстановлено

Проверено и исключено:

- **UTF-8 кириллица** — 35 серий, все либо XMP, либо мусор. Русских пунктов меню нет.
- **UTF-16LE кириллица** — 45 серий вида `U+04xx`, все короткие и бессмысленные
  (повторяющиеся `\x00\x04`). Это не строки, а данные.
- **Английские пункты** (`Aimbot`, `Wallhack`, `Triggerbot`, `Autofarm`, `ESP`, `FOV`,
  `Farm`) — 0 совпадений. `ESP` встречается 57 раз, но **всегда** внутри
  `OCSP_BASICRESP_*` / `OCSP_RESPONSE_*` из OpenSSL. `FOV` — только
  `SERVERINFOV2 FOR `. `Menu` — 6 раз, все из самого ImGui (`##ContextMenu`,
  `##MainMenuBar`, `Calling EndMenu() in wrong window!`).
- **Однобайтовый XOR** — прогнал все 255 ключей по `Aimbot`, `Wallhack`, `Triggerbot`,
  `Autofarm`, `Крест` (UTF-8). **0 попаданий.**
- **Реверс строк** — 0.

Вывод: строки чита либо собираются в рантайме, либо приходят извне (конфиг/сервер),
либо лежат в сжатом виде. Механизм не установлен — врать не буду. Для задачи это
некритично: пункт меню всё равно не даёт протокола, а протокол найден в APK.

---

## 3. Black Russia: как реально устроены мини-игры

Вот это — воспроизводимая часть.

### 3.1. Класс-держатель

```
Lcom/blackhub/bronline/game/gui/minigameshelper/MiniGamesHelperWithJSON;
```

Дизассемблер `<init>` (classes4.dex):

```
0000: const-string  v0, 'guiManager'
000a: invoke-direct {v1}, Object;.<init>
0010: iput-object   v2, v1, MiniGamesHelperWithJSON;.guiManager : Lcom/blackhub/bronline/game/GUIManager;
0014: const/16      v2, #31
0018: iput          v2, v1, MiniGamesHelperWithJSON;.screenId : I
001c: return-void
```

**`screenId = 31`.** Это тот же числовой id, что и `interface_id` в пакете.

### 3.2. Режимы

`MiniGamesHelperEnum` (`classes4.dex`), `<clinit>`:

```
NONE          ordinal 0
SCREEN_PRIZE  ordinal 1
SCREEN_FINGER ordinal 2
SCREEN_UNTIE  ordinal 3
```

Выбор режима — по ключу **`g`** в входящем JSON
(`MiniGamesHelperViewModel$initJson$1.invokeSuspend`):

```
001c: const-string  v2, 'g'
0020: invoke-virtual {v1, v2}, JSONObject;.optInt
...
003e: if-eqz  v1, ...     ; g == 0
0044: if-eq  v1, v3, ...  ; g == 1
0048: if-eq  v1, v2, ...  ; g == 2
004c: sget-object ... MiniGamesHelperEnum;.NONE
0054: sget-object ... MiniGamesHelperEnum;.SCREEN_FINGER
005a: sget-object ... MiniGamesHelperEnum;.SCREEN_UNTIE
0060: sget-object ... MiniGamesHelperEnum;.SCREEN_PRIZE
```

**Честная оговорка:** `dexdis.py` печатает относительные переходы неверно (видно по
`goto v3, ->+1579`), поэтому точное соответствие `g=0/1/2` <-> `FINGER/UNTIE/PRIZE`
я **не подтвердил**. По порядку тел в коде наиболее вероятно
`0 -> SCREEN_FINGER`, `1 -> SCREEN_UNTIE`, `2 -> SCREEN_PRIZE`, но это гипотеза.
Проверяется одним живым пакетом (см. §6).

### 3.3. Полный список ключей входящего JSON (screenId 31)

Из `MiniGamesHelperViewModel$initJson$1` (все `const-string`):

```
g  h  s  n  r  q1  q2  q3  z  m  p_start  p_max  p_max_bar  p_title  p_tick  p_timer  x
```

Разбор по коду:

| Ключ | Тип (вызов) | Смысл по контексту |
|---|---|---|
| `g` | `optInt` | тип мини-игры (0/1/2) |
| `h` | `optString` | заголовок окна |
| `s` | `optInt` | номер стадии/шага |
| `n` | `optString` | имя/подпись, проверяется на непустоту и `!= "null"` |
| `r` | `optInt`, дефолт `-1` | id результата; `-1` = «ещё не завершено» |
| `q1` `q2` `q3` | `optDouble` | три числа — геометрия/зоны (вероятно границы «зелёной» зоны) |
| `z` | `optDouble` | четвёртое число — вероятно позиция/скорость ползунка |
| `m` | `optString` | вспомогательная строка (модель/картинка) |
| `p_start` | `optInt` | стартовое значение шкалы |
| `p_max` | `optInt`, дефолт `100` | максимум шкалы |
| `p_max_bar` | `optInt`, дефолт `100` | максимум полосы |
| `p_title` | `optString` | подпись шкалы |
| `p_tick` | `optInt` | шаг шкалы |
| `p_timer` | (есть в пуле) | таймер |
| `x` | (есть в пуле) | не разобрано |

Проверка `n` в коде: `length > 0 && n != "null" && r != -1` — только тогда
запрашивается отрисовка через `GameRender.getInstance().RequestRender(...)`.

### 3.4. Что клиент отправляет обратно

`MiniGamesHelperWithJSON`, все методы целиком:

| Метод | JSON | Когда |
|---|---|---|
| `sendLineHit` | `{"s": 1}` | попадание по линии/в зону |
| `sendLineNotHit` | `{"s": 0}` | промах |
| `sendEndOfTime` | `{"t": 1}` | время вышло |
| `sendIfUntieScreen` | `{"t": 1}` | экран «развязывания» |
| `sendCloseScreen` | `{"c": 1}` | закрыть |

Все уходят через `GUIManager.sendJsonData(screenId=31, jsonObject)`.

**Вот оно, автопрохождение.** Сервер присылает геометрию (`q1..q3`, `z`, `p_*`) и ждёт
`{"s":1}`. Никакого клика по экрану не нужно — достаточно отправить байт. Проверка
попадания происходит **на сервере** (клиент только сообщает результат), поэтому
отправить `{"s":1}` можно сразу, не считая позицию ползунка.

### 3.5. Транспорт

Из `samp/interfaces.py` проекта (совпадает с тем, что делает APK):

```
пакет: 0x1B  USER_INTERFACE_SYNC
        u16  interface_id   (LE)
        u32  length         (LE)
        bytes JSON UTF-8
```

Сборка:

```python
payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
packet  = bytes([0x1B]) + struct.pack("<HI", interface_id, len(payload)) + payload
```

Разбор входящего — `samp/interfaces.py:parse_json_payload`, дальше
`packet_handler.py:546` эмитит `onReceiveJSON(interface_id, json)`.

Коды пакетов (`samp/constants.py:152`):

```
USER_INTERFACE_SYNC = 0x1B
RPC                 = 0x0B
UNOCCUPIED_SYNC     = 0x20
```

### 3.6. Таблица screenId

Собрал механически: для каждого класса `*WithJSON` взял последнюю `const` перед
`iput ... screenId` в `<init>`. Метод грубый — там, где в `<init>` есть другие
константы, значение может быть чужим. **Достоверны только те, что совпали с уже
проверенной таблицей проекта** (помечены галочкой) **и `MiniGamesHelper = 31`**
(проверен дизассемблером вручную).

| screenId | Класс | Статус |
|---|---|---|
| 0 | `taxirating/TaxiRatingActionWithJSON` | не проверено |
| 1 | `plates/PlatesActionWithJSON`, `rent/RentActionWithJSON` | не проверено |
| 2 | `fuelfill/FuelFillActionWithJSON`, `taxiorder/...` | не проверено |
| 6 | `rent/RentActionWithJSON`, `holidayevents/...` | не проверено |
| 8 | `holidayevents/HolidayEventsActionsWithJSON` | не проверено |
| 13 | `notification/NotificationActionWithJSON` | подтверждено |
| 14 | `electric/ElectricActionWithJSON` (+ `interactionwithnpc`, `plates`, `rent`, `radialmenuforcar`, `woundsystem`) | не проверено (электрик) |
| 16 | `taxi/TaxiActionWithJSON` | не проверено |
| 17 | `taxiorder/TaxiOrderActionWithJSON` | не проверено |
| 21 | `taximap/TaxiMapActionWithJSON` | не проверено |
| 22 | `donate/network/DonateActionWithJSON`, `blackpass/...` | подтверждено |
| 28 | `tuning/network/TuningActionWithJSON` | не проверено |
| **31** | **`minigameshelper/MiniGamesHelperWithJSON`** | **подтверждено дизассемблером** |
| 34 | `inventory/network/CarTrunkOrClosetActionsWithJSON` | не проверено |
| 39 | `tutorialhints/TutorialHintActionWithJSON` | подтверждено |
| 42 | `entertainmentsystem/...` | не проверено |
| 46 | `fractions/network/FractionActionsWithJSON` | не проверено |
| 49 | `craft/CraftActionWithJSON` | не проверено |
| 52 | `socialnetworklink/network/SocialNetworkActionWithJSON` | не проверено |
| 57 | `catchstreamer/CatchStreamerActionWithJSON` | не проверено |
| 59 | `fishing/FishingActionWithJSON` | не проверено (рыбалка) |
| 61 | `youtubeplayer/YoutubePlayerActionWithJSON` | не проверено |
| 63 | `interactionwithnpc/InteractionWithNpcActionWithJSON` | подтверждено |
| 64 | `halloweenaward/HalloweenAwardActionWithJSON` | не проверено |
| 65 | `activetask/ActiveTaskActionWithJSON` | подтверждено |
| 66 | `admintools/AdminToolsActionWithJSON` | не проверено |
| 68 | `upgradeobjectevent/UpgradeObjectEventActionWithJSON` | не проверено |
| 69 | `gifts/GiftsActionWithJSON` | не проверено |
| 70 | `panelinfo/PanelInfoActionWithJSON` | не проверено |
| 71 | `calendar/network/CalendarActionWithJSON` | не проверено |
| 73 | `cases/network/CasesActionWithJSON` | подтверждено |
| 74 | `bprewards/BpRewardsActionWithJSON` | подтверждено |
| 75 | `tanpinbanner/TanpinBannerActionWithJSON` | не проверено |

Мусорные значения (`67960846`, `327694`, `808`, `None`) — артефакт эвристики,
в таблицу не включены.

### 3.7. Где `screenId` превращается в окно

`GUIManager.createGuiFromId` (`gui2.txt:460`) — явная цепочка сравнений
`3, 4, 5, 15, 23, 26, 31, 41`, затем `packed-switch`. Тела в порядке:

```
BrDialogWindow, BrAudioDialog, BrDialogPipes, BrDialogWires, GUIVipAccount,
GUIMiniGameEventsGame, BrNewCaptcha, BrDialogSawmill, BrDialogDance,
BrDialogRobbery, BrDialogHack, BrDialogDiner
```

`31` в цепочке присутствует — согласуется с `MiniGamesHelper`.

Рядом — `showGUI(screenId = ...)`, `closeGUI(screenId = ...)`,
`sendJsonData(screenId = ...)`, `onPacketIncoming(screenId = ...)`,
`BAD VERSION, screenId = ` (строка в `classes4.dex`).

---

## 4. Сопоставление с проектом

`samp/interfaces.py:8` — текущая таблица:

```python
class InterfaceID:
    AUTH = 38;  SPAWN_SELECT = 50;  NOTIFICATION = 13;  DONATE_MENU = 22
    CASES = 73; QUEST_TASK = 39;    CINEMATIC = 76;     NPC_DIALOG = 63
    DIALOG_NPC = 114; CALL_NOTIFICATION = 65; REWARD = 74; SHOP_FOOD = 3
    DIALOG_MENU = 10; PASSWORD = 50
```

**`31` здесь отсутствует** — мини-игры протоколом не обрабатываются.

Подтверждение: по всему проекту (`bot.py`, `logic/`, `samp/`) нет ни `p_start`, ни
`q1/q2/q3`, ни `"s": 1`, ни `onHitLine`. То есть в README заявлена «мини-игра добычи
руды (попадание в зелёную зону)» в `QuestMasterTask`, но на уровне JSON она не
реализована — только перемещение по координатам и диалоги.

`logic/json_ui.py` знает `39`, `63`, `65`, `114`, `73`, `74`, `22`, `13`. `31` — нет.

---

## 5. Реализуемо ли в Python-клиенте

**Да.** Механика полностью серверная, клиент — тонкий.

Минимум, который нужен:

```python
# interface_id 31, тот же пакет 0x1B, что уже умеет samp/session.py:send_json
session.send_json(31, {"s": 1})   # попадание
session.send_json(31, {"c": 1})   # закрыть
```

Обработчик входящего:

```python
def on_interface_31(json_obj):
    if json_obj.get("o") == 1:                 # открытие
        g = json_obj.get("g")                  # 0/1/2 -> режим
        if g in (0, 1, 2):
            session.send_json(31, {"s": 1})    # сразу сообщаем попадание
```

Почему это проходит: `sendLineHit` — это обычный `put("s", 1)`, никакой локальной
проверки геометрии перед отправкой в коде нет. `q1/q2/q3/z/p_*` нужны только для
отрисовки, а вердикт выносит сервер.

Ограничения, которые надо держать в голове:

- **Тайминг.** `sendEndOfTime` (`{"t":1}`) шлётся, когда истекает `p_timer`.
  Если отвечать `{"s":1}` мгновенно на каждое открытие, это может выглядеть
  нечеловечески. Разумно ждать `0.3–0.8 * p_timer`.
- **`g` не подтверждён.** Пока не снят живой пакет, неясно, какое значение
  соответствует какой мини-игре. Безопасно реагировать на любое `g` из `{0,1,2}`.
- **«Кресты» не опознаны по имени.** Если это отдельный `screenId`, а не `31`,
  он найдётся тем же способом — по одному входящему пакету.

---

## 6. Как закрыть оставшиеся дырки (без сети, по докам проекта)

1. Включить `BR_TRACE_JSON=1` — `bot.py:1893` уже логирует `[ТРЕЙС] iid=... <json>`.
   Один прогон квеста даст точный `iid`, `g` и полный набор ключей для «крестов».
2. Сверить `g` с тем, какое окно открылось (`MiniGamesHelperEnum`).
3. Если `iid` окажется не `31` — искать класс `*WithJSON` с этим номером в таблице §3.6.

Это единственный способ, потому что в клиенте строки «кресты» нет физически.

---

## 7. Что осталось непонятным (честно)

| Вопрос | Статус |
|---|---|
| Что такое «кресты дяди Славы» в терминах клиента | **Не найдено.** Слова нет ни в одном из 5149 файлов APK. Вероятно серверный текст квеста |
| Какой `screenId` у «крестов» | **Не установлено.** `31` — единственная найденная мини-игра, но привязка к «крестам» не доказана |
| Точное соответствие `g` <-> `FINGER/UNTIE/PRIZE` | **Не подтверждено** — `dexdis.py` врёт в относительных переходах |
| Пункты меню Photon | **Не восстановлены.** Строк чита в бинаре нет в открытом виде (проверены UTF-8, UTF-16LE, XOR x255, реверс) |
| Флаг/офсет, связанный с «крестами» в Photon | **Не найден.** Прятать нечего: самих строк нет |
| Как Photon обходит пейволл | **Не разобрано.** Найдены только PNG-картинки пейволла, не логика проверки |
| RPC/пакеты, которыми Photon шлёт автопрохождение | **Не установлено.** В бинаре есть libcurl + nlohmann::json + base64, что намекает на HTTP-канал, но подтвердить нечем |
| `p_timer`, `x` в JSON мини-игры | Ключи найдены, семантика не разобрана |
| Значения `ScreenId` (81 поле) | Имена полей прочитать не удалось (нужна аккумуляция `field_idx_diff`), значения — `encoded_array` не разобрал. Таблица в §3.6 собрана обходным путём и помечена как приблизительная |

---

## 8. Приложение: воспроизводимость

Всё вышеперечисленное получено этими командами (ничего не меняет в проекте):

```bash
# строки во всех записях APK
python3 - <<'EOF'
import zipfile
z=zipfile.ZipFile('br.apk')
for n in z.namelist():
    if n.endswith('/'): continue
    b=z.read(n)
    if 'крест'.encode() in b or 'слав'.encode() in b:
        print(n, len(b))
EOF

# пул строк dex (проверка отсутствия кириллицы)
python3 -c "import sys; sys.path.insert(0,'.'); from dexparse import Dex; d=Dex(open('classes4.dex','rb').read()); print(d.string_ids_size)"

# глобальный пул resources.arsc
python3 -c "import sys; sys.path.insert(0,'.'); from axml import load_apk; g=load_apk('br.apk')[1].global_strings; print(len(g))"

# screenId мини-игр
python3 dexdis.py classes4.dex "MiniGamesHelperWithJSON"
python3 dexdis.py classes4.dex 'minigameshelper/MiniGamesHelperViewModel$initJson$1;'
```

Ключевые адреса для повторной проверки:

```
libPhoton.so   JNI_OnLoad              0x449a64
               Dear ImGui 1.93.0 WIP   0x1f133e
               crossCertificatePair    0x1fbc3f   (ложное срабатывание)
               XMP-пейволл             0x221103, 0x221190, 0x22efa3, 0x22f031
               base64-алфавит          0x27b264
               Dobby InterceptRouting  0x279b80
               Dobby InlineHookRouting 0x279ba9
               nlohmann json           0x23cad4
               .text                   0x41db00 .. 0xdd9ea0
               .rodata                 0x1ad000 .. 0x35a62b
               .data (TTF)             0xe866d8, Manrope-Bold @ 0xe8d522
```

---

## 9. Итог одной фразой

Автопрохождение в BR не требует ни хуков, ни чтения памяти — сервер сам присылает
геометрию мини-игры в `interface_id=31`, а вердикт о попадании принимает от клиента
по `{"s":1}`. Photon, скорее всего, делает ровно это, только с обфускацией; «кресты»
как строки в клиенте не существуют, поэтому привязку к конкретной стадии квеста
даёт только один снятый пакет.
