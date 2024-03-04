<h1>mitigator_response</h1>
Скрипт для реагирования в <a href="https://go.kaspersky.com/ru-kuma" target="_blank">SIEM KUMA</a>, который осуществляет временную блокировку в программном комплексе для защиты от DDoS-атак <a href="https://docs.mitigator.ru/">BIFIT MITIGATOR</a><br>

Временная блокировка трафика (tbl) в политике, которая подпадает под указанные параметры (src_ip, dst_ip, src_port, dst_port, protocol) или же в указанной в реагировании политике.

***ВНИМАНИЕ!  С UDP аккуратнее - можно случайно зафильтровать спуфленные адреса***

<h1>Ключи для запсука скрипта</h1>

```bash
--server указываем ip адрес сервера, можно захаркодить в скрипте в hostnames = ['x.x.x.x', 'y.y.y.y'] # Вставить список хостов 
--user указываем имя пользователя, можно захаркодить в скрипте в user = 'login' # Заменить логин
--password указываем имя пользователя, можно захаркодить в скрипте в passwd = 'passwd' # Заменить пароль
--policy указываем policy_id, если известно заранее
-s, --ip_src IP адрес источника для блокировки
-d, --ip_dst IP адрес назначения для блокировки
-t, --time время на которое будет заблокирован трафик
-p, --port_src Порт источника для блокировки
-o, --port_dst Порт назначения для блокировки
-P, --protocol Протокол для блокировки
```

<h1>Пример запуска скрипта</h1>

```bash
./mitigator_response.py -s 1.1.1.1 -t 300 -d 2.2.2.2 -p 80 -o 80 -P TCP --server 172.16.1.20 --user admin --password admin --policy 10
```

<h1>Аргументы запуска скрипта в KUMA</h1>

```python
-s {{.SourceAddress}} -t 300 -d {{.DestinationAddress}} -p {{.DestinationPort}} -o {{.SourcePort}} -P {{.TransportProtocol}} --server SERVERNAME --user USER --password PASSWORD --policy POLICY_ID
```

![image](https://github.com/IODaksf/kuma_mitigator_response/assets/162118316/ebd70abc-19fc-4e8f-8f57-6f55938c3a8b)
