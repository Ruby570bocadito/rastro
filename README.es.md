# Rastro

[![tests](https://github.com/Ruby570bocadito/rastro/actions/workflows/tests.yml/badge.svg)](https://github.com/Ruby570bocadito/rastro/actions/workflows/tests.yml)
[![python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://github.com/Ruby570bocadito/rastro/blob/main/pyproject.toml)
[![licencia: Apache-2.0](https://img.shields.io/badge/licencia-Apache--2.0-blue.svg)](https://github.com/Ruby570bocadito/rastro/blob/main/LICENSE)

**Pega un enlace de phishing. Mira cómo se despliega la campaña entera.**

[English](https://github.com/Ruby570bocadito/rastro/blob/main/README.md) · Español

![Rastro desplegando una campaña de phishing inventada: diez lanzamientos alrededor de una misma plantilla de nombres, y las deducciones de Husmo](https://raw.githubusercontent.com/Ruby570bocadito/rastro/main/docs/demo-unfold.gif)

Un SMS de phishing es un enlace. Detrás suele haber una banda que ha registrado decenas de dominios con la misma plantilla, lanzamiento tras lanzamiento, y que mañana registrará el siguiente. Rastro parte de ese único enlace y te da, en un expediente que no depende de nada más:

- **la banda y la campaña**: todos los dominios construidos con la misma plantilla de nombres, y los que se unen a tu enlace por pistas que suman (un certificado compartido, el mismo servidor, la misma sesión de trabajo);
- **dónde trabaja la banda**: el huso horario de su jornada, leído de los momentos en que registró dominios y pidió certificados, con un «no concluyente» honesto cuando no hay datos suficientes;
- **su próximo dominio**: un patrón estrecho que vigilar en Certificate Transparency y que caza el siguiente dominio falso en cuanto recibe su certificado;
- **a quién avisar**: un borrador de aviso de abuso por registrador para los dominios que siguen activos.

Husmo, un hurón detective, explica cada deducción y cuánta seguridad tiene. Rastro nunca se conecta a los dominios, nunca busca a las personas que hay detrás y nunca envía nada por ti.

> Estado: 0.1, temprano. Cada pieza se validó antes con datos reales, pero habrá asperezas.

## Pruébalo en 30 segundos

Python 3.11 o superior, sin dependencias.

```bash
pipx install rastro-osint
```

```bash
rastro demo --open --lang es
```

También vale `pip install rastro-osint`, o instalarlo directamente desde GitHub con `pip install git+https://github.com/Ruby570bocadito/rastro`.

La demo es un caso inventado. Sus marcas no existen, sus dominios acaban en `.test` (reservado, así que nadie puede registrar uno), sus direcciones son de los rangos reservados para documentación y su banda está simulada en UTC+3, de lunes a viernes. El expediente marca esa verdad bajo el mapa, para que compares la respuesta de Rastro con la realidad.

![El mapa cerrándose sobre el huso de la banda, y la línea de tiempo de sus lanzamientos](https://raw.githubusercontent.com/Ruby570bocadito/rastro/main/docs/demo-map.gif)

## Cómo funciona

```mermaid
flowchart LR
    link["Enlace de phishing"] --> seed["Dominio semilla<br/>y marca"]
    seed --> siblings["Hermanos: lista pública,<br/>vigilante, certificados compartidos"]
    siblings --> profiles["Primer certificado: crt.sh<br/>Registro: RDAP<br/>Servidores: DNS público"]
    profiles --> crew["Banda y campaña"]
    crew --> clock["Mapa del huso"]
    crew --> next["Patrón del próximo dominio"]
    crew --> drafts["Borradores de aviso"]
```

1. **Hermanos.** Dominios parecidos construidos como la semilla (misma marca y plantilla, o la misma palabra rara) en una lista pública de phishing, en lo que guardó el vigilante y entre los nombres que compartieron certificado con ella.
2. **Perfiles.** De cada uno: su primer certificado (crt.sh), su registro y su registrador (RDAP), y sus direcciones y servidores de nombres (el DNS sobre HTTPS de Cloudflare). Contestan los registros y el resolvedor, nunca el dominio.
3. **Banda y campaña.** La banda son todos los dominios construidos con la plantilla estrecha de la semilla, a veces a lo largo de años. La campaña es el grupo de la semilla cuando se agrupan las pistas que suman:

   | Pista | Peso |
   |---|---|
   | certificado compartido | 1,0 |
   | la misma palabra larga y rara junto a la marca | 1,0 |
   | misma plantilla | 0,5 |
   | misma sesión de trabajo (30 minutos) | 0,5 |
   | mismo lanzamiento (cada dominio a menos de 72 horas del anterior) | 0,5 |
   | misma dirección o mismos servidores de nombres | según lo raros que sean |

   Las parejas que llegan a 1,0 entran en la misma campaña. Una plantilla sola nunca une dos dominios.
4. **El reloj.** Los registros y los primeros certificados son actos de la propia banda, así que siguen su jornada. Rastro los agrupa en sesiones de trabajo, puntúa los 24 husos nominales frente a una jornada típica (teniendo en cuenta los bots y las bandas que empiezan antes o después) y los contrasta con una actividad uniforme durante todo el día. Con sesiones suficientes lee también el fin de semana y el horario de verano. Por debajo de lo que los experimentos vieron necesario, cada pista responde «no concluyente».
5. **El próximo dominio.** Una expresión regular legible aprendida de los nombres de la banda. Solo se arma si es estrecha (como mucho 10^9 nombres posibles), porque las anchas daban miles de falsas alarmas al día.
6. **Los borradores.** Uno por registrador, con las pruebas, para los dominios que siguen registrados. Los caducados, suspendidos, defensivos y vueltos a registrar quedan fuera, cada uno con su motivo.

## Investiga un enlace real

```bash
rastro investigate "hxxps://dominio-falso[.]example/ruta" --lang es
```

Pega el enlace tal como llegó, desactivado o no. Husmo cuenta el resultado en la terminal y el caso queda en `data/raw/reports/<dominio>.html`.

El expediente lleva dentro sus datos, estilos y script, con una Content-Security-Policy que prohíbe cualquier petición de red, así que abrirlo no contacta con nadie. Nunca contiene la ruta del enlace, que suele llevar un token que identifica a quien lo recibió, y escribe todo texto controlado por los atacantes como texto, nunca como HTML.

`--list FICHERO` indica la lista de phishing en la que buscar: por defecto `data/raw/lists/phishing-domains-ACTIVE.txt` si existe, por ejemplo la de [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database). `--db` añade lo que guardó el vigilante, `--json FICHERO` guarda los datos del caso, `--offline` usa solo respuestas guardadas, y `--no-crtsh`, `--no-rdap` y `--no-dns` se saltan una fuente.

## Vigila Certificate Transparency

```bash
rastro watch --learn dominios-campaña.txt --follow --minutes 60 --db data/ct.sqlite --alerts alertas.jsonl --bursts-every 10
```

Rastro lee los registros de Certificate Transparency directamente, con la API estática de CT, y sigue el ritmo del registro de Let's Encrypt en tiempo real.

- Solo arma patrones estrechos y dice cuáles se salta; `--allow-broad` lo fuerza.
- Los dominios oficiales de las marcas nunca dan alerta, y `--allow FICHERO` añade los tuyos.
- Cada dominio alerta una sola vez, aunque lleguen al registro su precertificado y su certificado.
- `--bursts-every` busca, sin semilla, varios dominios nuevos de una misma marca construidos con la misma plantilla, y da el patrón listo para armar.
- Con `--db` retoma donde lo dejó y guarda solo los certificados con un dominio falso de marca o que dieron alerta: entre el 0,2 y el 0,4 % del registro, decenas de MB al día en vez de unos 6 GB. `--store-all` lo guarda todo.
- Sin `--follow` lee las últimas `--tiles` teselas y para. `rastro logs` lista los registros actuales, que cambian cada seis meses.

## Otros comandos

| Comando | Qué hace |
|---|---|
| `rastro campaigns --domains FICHERO --dns` | agrupa dominios en campañas, desde una lista o desde lo que guardó el vigilante (`--db`) |
| `rastro bursts --db data/ct.sqlite --hours 24` | busca campañas naciendo entre los nombres que guardó el vigilante |
| `rastro pattern FICHERO` | aprende el patrón de nombres de una campaña y dice cuántos nombres podría cazar |
| `rastro rhythm FICHERO` | estima el huso de una banda a partir de horas UTC, con las pistas de fin de semana, horario de verano y festivos |

## Validado con datos reales

Cada pieza se probó con campañas reales antes de entrar en el producto. Los detalles, y lo que falló, están en [experiments](https://github.com/Ruby570bocadito/rastro/blob/main/experiments/README.md) (en inglés).

| Pregunta | Respuesta |
|---|---|
| ¿Muestran las bandas una jornada laboral en las horas de sus primeros certificados? | Sí en 3 de 4 familias de plantilla, tras corregir por comparaciones múltiples. La familia de Coinbase trabaja en torno a UTC−7 |
| ¿Caza un patrón aprendido los demás dominios de una campaña sin cazar otros? | Los patrones estrechos cazan una mediana del 87 %, sin coincidencias de fuera |
| ¿Cuántas veces saltarían con certificados nuevos? | Los estrechos: 0 de 30.720. Los anchos: unas 6.600 falsas alarmas al día, así que solo se arman los estrechos |
| ¿Se parten las familias de plantilla en campañas? | Sí: una familia era un único lanzamiento de 68 dominios, otra llegó en oleadas |
| ¿Cuántos datos necesitan las pistas de calendario? | El fin de semana, unas 50 sesiones en 8 semanas. El horario de verano, cientos |
| ¿Se despliega un enlace de principio a fin? | Un dominio falso de Coinbase cazado en vivo, que no estaba en la lista pública, se desplegó en una banda de 95 dominios. Solo él seguía activo, y el reloj volvió a dar UTC−7 |
| ¿Detecta un modelo solo con el nombre el phishing entre los certificados nuevos? | Todavía no: AUC 0,79 con plantillas nuevas, pero con cualquier umbral de menos de unas 7.000 falsas alarmas al día no cazó ninguno de los nombres frescos de la lista. No se incluye ningún modelo de nombres hasta que tenga nombres benignos limpios de los que aprender |
| ¿Se expande una URL a sus hermanos con urlscan? | Pendiente |

## Lo que Rastro nunca hará

- Identificar personas. Se queda en husos horarios e infraestructura.
- Conectarse a la infraestructura de los atacantes, o usar credenciales encontradas en kits de phishing.
- Enviar nada en tu nombre: los avisos de abuso son borradores.
- Publicar análisis de URL que contengan datos de víctimas.

## Hoja de ruta

- Expansión desde una URL con urlscan, para campañas que cambian de nombres pero no de página.
- Un modelo de nombres que merezca la pena incluir: el experimento 07 mostró que antes necesita nombres benignos limpios, como dominios registrados hace años y nunca listados.
- Husmo leyendo en voz alta sus deducciones en el expediente.
- Seguimiento de los avisos de abuso, para medir cuánto tarda cada registrador en actuar.

## Desarrollo

```bash
git clone https://github.com/Ruby570bocadito/rastro
```

```bash
pip install -e ./rastro pytest
```

```bash
python -m pytest rastro
```

Los tests usan solo datos sintéticos: sin red y sin claves. [CONTRIBUTING.md](https://github.com/Ruby570bocadito/rastro/blob/main/CONTRIBUTING.md) explica la estructura y las reglas que respeta cada cambio.

## Seguridad

Para avisar de una vulnerabilidad en el propio Rastro, mira [SECURITY.md](https://github.com/Ruby570bocadito/rastro/blob/main/SECURITY.md).

## Licencia

[Apache-2.0](https://github.com/Ruby570bocadito/rastro/blob/main/LICENSE). Copyright 2026 Ruby570bocadito.

El contorno de tierra del mapa viene de [Natural Earth](https://www.naturalearthdata.com/) (dominio público), a través del paquete world-atlas.
