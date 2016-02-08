#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Debe ejcutarse como root o el escaneo no mostrará resultados.
# La bilioteca markup.py [1] se encuentra instalada en /usr/lib/python2.7/
# conmo un archivo del mismo nombre, ya que la instalación mediante pip
# fallaba. [1] http://markup.sourceforge.net/

import sys, logging, time, csv, ConfigParser
#cambiar markup por lib.markup
import markup as markup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

users = {}
connected_users = []
name = ""
nobody = ["Parece que no hay nadie."]

#Vuelca en una variable ConfigFile el contenido del archivo de config.
def read_config_file():
    cfg = ConfigParser.ConfigParser()
    cfg.read(["config.cfg"])
    return cfg

#Obtiene de un csv la información de los miembos de sugus y la almacena en users
def fill_users_dictionary(cfg):
    users_directory = cfg.get("usersfile", "directory")

    if users_directory == "-":
        users_filename = cfg.get("usersfile", "file")
    else:
        users_filename = directory + "/" + cfg.get("usersfile", "file")

    with open(users_filename, 'rb') as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        next(reader, None)
        for row in reader:
            if row[1] == 'True':
                users[str(row[0])] = str(row[2])

#Realiza un escaneo ARP y filtra las MACs según aparezcan en users
def get_connected_users(cfg):

    ipdst = cfg.get("request", "ipdst")
    macdst = cfg.get("request", "macdst")
    timeout = cfg.get("request", "timeout")

    try:
        alive,dead=srp(Ether(dst=macdst)/ARP(pdst=ipdst), timeout=timeout, verbose=0)
        time.sleep(15)
        alive2,dead2=srp(Ether(dst=macdst)/ARP(pdst=ipdst), timeout=timeout, verbose=0)

        alive.extend(alive2)
        dead.extend(dead2)

        for i in range(0,len(alive)):
            if alive[i][1].hwsrc in users:
                name = users.get(alive[i][1].hwsrc)
                if name not in connected_users:
                    connected_users.append(name)
    except:
            pass
    	#raise

#Crea el archivo html con la información contenida en users y los parámetros del archivo de config.
def create_html(cfg):
    title = cfg.get("htmlfile", "title")
    charset=cfg.get("htmlfile", "charset")
    lang=cfg.get("htmlfile", "lang")
    header=cfg.get("htmlfile", "header")
    content=cfg.get("htmlfile", "content")

    html_directory = cfg.get("htmlfile", "directory")

    if html_directory == "-":
        hmtl_filename = cfg.get("htmlfile", "file")
    else:
        html_filename = html_directory + "/" + cfg.get("htmlfile", "file")

    page = markup.page()
    page.init(title=title,
            charset=charset,
            lang=lang
            # css=('one.css', 'two.css'),
    )
    page.h2(header)
    page.ul(class_='usuarios')
    if connected_users:
        page.li(connected_users)
    else:
        page.li(nobody)
    page.ul.close()
    page.p(content)

    with open(html_filename, 'w') as new_file:
        new_file.write(str(page))


config = read_config_file()
"""
fill_users_dictionary(config)
get_connected_users(config)
create_html(config)
"""
