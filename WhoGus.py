#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-

# Debe ejcutarse como root o el escaneo no mostrará resultados.
# La bilioteca markup.py [1] se encuentra instalada en /usr/lib/python2.7/
# conmo un archivo del mismo nombre, ya que la instalación mediante pip
# fallaba. [1] http://markup.sourceforge.net/

import codecs
import sys, logging, time, csv, configparser, os

#cambiar markup por lib.markup
#from markup import *
# import markdown as markdown
import traceback

import markup
from datetime import timedelta, datetime

from pip._vendor.cachecontrol.caches.file_cache import _secure_open_write

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

config_route = "myConfig.cfg"

#Vuelca en una variable ConfigFile el contenido del archivo de config.
def read_config_file():
    cfg = configparser.ConfigParser()
    cfg.read([config_route])
    return cfg

# Obtiene de un csv la información de los miembos de sugus y lo compara con los actualmente conectados
def link_found_mac_users(cfg, detected_macs):
    users_filename = cfg.get("usersfile", "route")
    known_users = []
    unknown_macs = []
    with open(users_filename, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        next(reader, None)
        csvContain = []
        for a in reader:
            if len(a) > 1:
                mac = a[0].replace(" ", "")
                if len(a) >= 3 and mac.count(":") == 5 and len(mac) == 17:
                    csvContain.append(a)
                else:
                    print("Incorrect entry: \n" + str(a))

        if len(csvContain) < 1:
            print("No Mac found in :" + users_filename)

        for row in detected_macs:
            for user in csvContain:
                if row == user[0].replace(" ", "").lower():
                    toImprove = user not in known_users
                    if str2bool(user[1]) and toImprove:
                        known_users.append(user)
                    break
            else:
                if row not in unknown_macs:
                    unknown_macs.append(row)

    return known_users, set(unknown_macs)

def str2bool(v):
  return v.lower().replace(" ", "") in ("yes", "true", "t", "1")


#Realiza un escaneo ARP
def get_connected_arp(cfg):

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

        detected_macs = set()
        for x in alive:
            detected_macs.add(x[1].hwsrc)

    except:
        print("Exception detected during arp scan: ")
        print(traceback.print_exc())
        raise
    else:
        return detected_macs

# Comprueba el DHCP ejecutando la orden del archivo config
def get_connected_dhcp(cfg):

    last_uptime_sec = int(cfg.get("dhcp", "last_uptime_sec"))
    sentence = cfg.get("dhcp", "sentence")

    try:
        macs = os.popen(sentence).read().split("\n")
        # print(macs.split("\n"))
        new_macs = []
        for i in macs:
            a = i.split(";")
            if len(a)>1:
                new_macs.append([a[0].strip(), a[1].strip()])

        detected_macs = set()
        limit_moment = datetime.utcnow() - timedelta(seconds=last_uptime_sec)
        for x in new_macs:
            # print("A leer: " + str(x) + "; actDate: " + limit_moment.strftime('%Y/%m/%d %H:%M:%S'))
            if x[0] > limit_moment.strftime('%Y/%m/%d %H:%M:%S'):
                print("x: " + str(x))
                detected_macs.add(x[1])

    except:
        print("Exception detected during dhcp lecture: ")
        print(traceback.print_exc())
        raise
    else:
        return detected_macs

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


def create_html_markdown(cfg, known_users):
    title = cfg.get("htmlfile", "title")
    html_filename = cfg.get("htmlfile", "route")

    html = """<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.01 Transitional//EN'>
            <html lang="es">
                <head>
                    <meta content="text/html; charset=utf-8" http-equiv="Content-Type" /> \n"""

    html += "<title>" + title + "</title>\n</head>\n"
    html += "<body>\n<h2>\n" + "Miembros actualmente en la asociación:" + "\n</h2>\n"
    html += """<ul class="usuarios">\n"""
    if known_users:
        toPrint = []
        for a in known_users:
            if a[2].strip() not in toPrint:
                html += "<li>" + a[2].strip() + "</li>\n"
                toPrint.append(a[2].strip())
    else:
         html += "<li>Parece que no hay nadie.</li>\n"

    html += "</ul>\n"
    html += """<p><strong>Nota: </strong>La lista indica con cierta seguridad que los miembros mostrados se encuentran
     en la asociación, pero que la lista este vacía no tiene por que reflejar que no haya nadie en ese momento.
     <br> <br> <strong><a href="http://sugus.eii.us.es">sugus.eii.us.es</a></strong></p>"""

    html += "</body>"

    with codecs.open(html_filename, "w", encoding="utf-8", errors="xmlcharrefreplace") as file:
        file.write(str(html))


def main():
    while True:
        config = read_config_file()

        print("\n["+ str(time.strftime('%H:%M:%S')) + "] Scanning...")
        try:
            detected_macs = set()

            # ARP scan
            if str2bool(config.get("request", "active")):
                detected_macs = get_connected_arp(config)

            #DHCP check
            if str2bool(config.get("dhcp","active")):
                detected_macs = set(detected_macs | get_connected_dhcp(config))

            # create_html(config)
            known_users, unknown_macs = link_found_mac_users(config, detected_macs)

            create_html_markdown(config, known_users)

            print("["+ str(time.strftime('%H:%M:%S')) + "] Found " + str(len(detected_macs)-len(unknown_macs)) + " known_mac and "
                  + str(len(unknown_macs)) + " unknown_macs")

        except KeyboardInterrupt:
            print("\nBye! \n")
            break
            pass
        except:
            print("Occur an error running the script: ")
            print(traceback.print_exc())
            pass

        print("["+ str(time.strftime('%H:%M:%S')) + "] Sleeping")
        try:
            time_sleep = int(config.get("general", "time_between_scans_sec"))
            time.sleep(time_sleep)
        except KeyboardInterrupt:
            print("\nBye! \n")
            break
            pass
        except:
            print("Error applying time_between_scans_sec: ")
            raise

if __name__ == '__main__':
    main()
