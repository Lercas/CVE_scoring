# CVE_scoring
Скрипт для корреляции между нашей системой скоринга и CVSS 3.0
## Установка
Для данного скрипта необходимо установить библиотеку `requests`.

Установка зависимостей с помощью команды:

```bash
pip install -r requirements.txt
```

Это установит библиотеку `requests` указанной версии, которая используется в скрипте для отправки запросов к API.


## Описание
Для учета наличия эксплойта и его возможностей в формуле расчета скоринга, мы можем добавить дополнительный коэффициент. Предлагаю использовать следующую формулу:

Наш скоринг = (CVSS 3.0 * 100) + (Exploitability * K)

где:
```
    CVSS 3.0 - оценка уязвимости по CVSS 3.0,
    Exploitability - балл, оценивающий степень эксплуатации уязвимости (от 0 до 100),
    K - коэффициент, определяющий влияние наличия эксплойта на итоговый скоринг (например, 0.5 или 1).
```
Пример:
```
    CVSS 3.0 оценка: 9.8
    Exploitability: 80
    K: 0.5
```
Наш скоринг = (9.8 * 100) + (80 * 0.5) = 980 + 40 = 1020

В этом случае, если уязвимость имеет высокий балл эксплуатации, ее итоговый скоринг будет увеличен.

## Что такое Exploitability
Exploitability - это показатель, который определяет, насколько легко уязвимость может быть эксплуатирована. Мы можем разработать свою схему оценки Exploitability, учитывая различные факторы, такие как:
```
    Наличие публичных эксплойтов: Если эксплойт доступен в открытом доступе, уязвимость становится более привлекательной для злоумышленников и значительно повышает риск эксплуатации.
    Сложность эксплуатации: Если эксплойт сложно внедрить или требует особых условий, это может снижать вероятность успешной эксплуатации.
    Требования к привилегиям: Если эксплойт требует высоких привилегий для выполнения (например, административных прав), это может снижать вероятность успешной эксплуатации.
    Взаимодействие с пользователем: Если эксплойт требует взаимодействия с пользователем (например, открытие файла или переход по ссылке), это также может снижать вероятность успешной эксплуатации.
```
Оценка Exploitability может быть представлена в виде числа от 1 до 100, где 1 означает наименьшую возможность эксплуатации, а 100 - наибольшую. Вот пример:
```
    Наличие публичных эксплойтов: 0 (нет) или 50 (да)
    Сложность эксплуатации: 0 (высокая) или 25 (низкая)
    Требования к привилегиям: 0 (высокие) или 15 (низкие)
    Взаимодействие с пользователем: 0 (требуется) или 10 (не требуется)
```
Exploitability = (публичные эксплойты) + (сложность эксплуатации) + (требования к привилегиям) + (взаимодействие с пользователем)

## Пример на CVE

В качестве примера возьмем уязвимость с идентификатором CVE-2021-44228, которая связана с библиотекой Apache Log4j 2.

Описание:
Эта уязвимость, известная как Log4Shell, позволяет удаленному злоумышленнику выполнить произвольный код на целевой системе с использованием специально сформированных сообщений, содержащих JNDI-запросы.
```
CVSS 3.0 оценка: 10.0 (критическая)
```
Exploitability: Эксплойты для этой уязвимости широко доступны, и она активно эксплуатируется злоумышленниками. Для этого примера, допустим, что Exploitability равна 90.

K (коэффициент): В нашем случае, возьмем K = 1 для упрощения.

Теперь применим нашу формулу:
```
Наш скоринг = (CVSS 3.0 * 100) + (Exploitability * K) = (10.0 * 100) + (90 * 1) = 1000 + 90 = 1090
```
