#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-

# Debe ejcutarse como root o el escaneo no mostrará resultados.
# La bilioteca markup.py [1] se encuentra instalada en /usr/lib/python2.7/
# conmo un archivo del mismo nombre, ya que la instalación mediante pip
# fallaba. [1] http://markup.sourceforge.net/

import codecs
import sys, logging, time, csv, configparser

#cambiar markup por lib.markup
#from markup import *
# import markdown as markdown
import markup

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

config_route = "config.cfg"

#Vuelca en una variable ConfigFile el contenido del archivo de config.
def read_config_file():
    cfg = configparser.ConfigParser()
    cfg.read([config_route])
    return cfg

# Obtiene de un csv la información de los miembos de sugus y lo compara con los actualmente conectados
def link_found_mac_users(cfg, known_users, detected_macs, unknown_macs):
    users_filename = cfg.get("usersfile", "route")

    with open(users_filename, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        next(reader, None)
        csvContain = []
        for a in reader:
            csvContain.append(a)

        for row in detected_macs:
            for user in csvContain:
                if row[1].hwsrc == user[0].replace(" ", "").lower():
                    if str2bool(user[1]) and user not in known_users:
                        known_users.append(user)
                    break
            else:
                if row[1].hwsrc not in unknown_macs:
                    unknown_macs.append(row[1].hwsrc)

    print("Known Macs (Apróx): " + str(len(known_users)))
    print("Unknown Macs (Apróx): " + str(len(unknown_macs)))


def str2bool(v):
  return v.lower().replace(" ", "") in ("yes", "true", "t", "1")


#Realiza un escaneo ARP y filtra las MACs según aparezcan en users
def get_connected_users(cfg, detected_macs):

    ipdst = cfg.get("request", "ipdst")
    timeout = int(cfg.get("request", "timeout"))
    interface = cfg.get("request", "interface")
    if interface == "":
        interface = None

    try:
        alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipdst), timeout=timeout, iface=interface, verbose=0)
        time.sleep(15)
        alive2, dead2 = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipdst), timeout=timeout, iface=interface, verbose=0)

        alive.extend(alive2)
        # dead.extend(dead2)

        detected_macs.extend(alive)

    except:
        print("Exception detected: ")
        print(traceback.print_exc())
        pass

#Crea el archivo html con la información contenida en users y los parámetros del archivo de config.
# def create_html(cfg):
#     title = cfg.get("htmlfile", "title")
#     charset=cfg.get("htmlfile", "charset")
#     lang=cfg.get("htmlfile", "lang")
#     header=cfg.get("htmlfile", "header")
#     content=cfg.get("htmlfile", "content")
#
#     html_filename = cfg.get("htmlfile", "route")
#
#     page = markup.page()
#     page.init(title=title,
#             charset=charset,
#             lang=lang
#             # css=('one.css', 'two.css'),
#     )
#     page.h2(header)
#     page.ul(class_='usuarios')
#     if connected_users:
#         page.li(connected_users)
#     else:
#         page.li(nobody)
#     page.ul.close()
#     page.p(content)
#
#     with open(html_filename, 'w') as new_file:
#         new_file.write(str(page))


def create_htmlMarkdown(cfg, known_users):
    title = cfg.get("htmlfile", "title")
    charset=cfg.get("htmlfile", "charset")
    lang=cfg.get("htmlfile", "lang")
    header=cfg.get("htmlfile", "header")
    content=cfg.get("htmlfile", "content")

    html_filename = cfg.get("htmlfile", "route")
    html = """<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN'>
            <html lang="es">
                <head>
                    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" /> \n"""

    html += "<title>" + title + "</title>\n</head>\n"
    html += "<body>\n<h2>\n" + "Miembros actualmente en la asociación:" + "\n</h2>\n"
    html += """<ul class="usuarios">\n"""
    if known_users:
        for a in known_users:
            html += "<li>" + a[2] + "</li>\n"
    else:
         html += "<li>Parece que no hay nadie.</li>\n"

    html += "</ul>\n"
    html += """<p><strong>Nota: </strong>La lista indica con cierta seguridad que los miembros mostrados se encuentran
     en la asociación, pero que la lista este vacía no tiene por que reflejar que no haya nadie en ese momento.
     <br> <br> <strong><a href="http://sugus.eii.us.es">sugus.eii.us.es</a></strong></p>"""

    html += "</body>"

    with codecs.open("newhtml.html", "w", encoding="utf-8", errors="xmlcharrefreplace") as file:
        file.write(str(html))


def main():
    detected_macs = []
    known_users = []
    unknown_macs = []

    config = read_config_file()

    get_connected_users(config, detected_macs)
    # create_html(config)
    link_found_mac_users(config, known_users, detected_macs, unknown_macs)

    create_htmlMarkdown(config, known_users)

if __name__ == '__main__':
    main()
