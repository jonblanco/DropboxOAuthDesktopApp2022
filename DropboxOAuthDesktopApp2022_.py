import requests
import urllib
import webbrowser
import socket
import json


app_key = "msdbmzp7zq91t8s"
app_secret = "nsffot6klzd9jvu"
server_addr = "localhost"
server_port = 8090
redirect_uri = "http://" + server_addr + ":" + str(server_port)


def local_server():
    # sartu kodea hemen

    # 8090. portuan entzuten dagoen zerbitzaria sortu
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.bind((server_addr, server_port))
    listen_socket.listen(1)
    print("\t\tSocket listening on port " + str(server_port))

    # nabitzailetik 302 eskaera jaso
    # ondorengo lerroan programa gelditzen da, zerbitzariak 302 eskaera jasotzen duen arte
    client_connection, client_address = listen_socket.accept()
    eskaera = client_connection.recv(1024).decode()
    print("\t\tNabigatzailetik ondorengo eskaera jaso da:")
    print("\n" + eskaera)

    # eskaeran "auth_code"-a bilatu
    lehenengo_lerroa = eskaera.split('\n')[0]
    aux_auth_code = lehenengo_lerroa.split(' ')[1]
    auth_code = aux_auth_code[7:].split('&')[0]
    print("auth_code: " + auth_code)

    # erabiltzaileari erantzun bat bueltatu
    http_response = """\
    HTTP/1.1 200 OK

    <html> 
    <head>
    <title>Proba</title>
    </head> 
    <body> The authentication flow has completed. Close this window. </body> 
    </html>
    """
    client_connection.sendall(str.encode(http_response))
    client_connection.close()

    return auth_code


def do_oauth():
    # Authorization
    # sartu kodea hemen

    uri = "https://www.dropbox.com/oauth2/authorize"
    datuak = {'response_type': 'code',
              'client_id': app_key,
              'redirect_uri': redirect_uri}
    datuak_kodifikatuta = urllib.parse.urlencode(datuak)
    step2_uri = uri + '?' + datuak_kodifikatuta
    print("\t" + step2_uri)
    webbrowser.open_new(step2_uri)  # eskaera nabigatzailean egin

    auth_code = local_server()

    # Exchange authorization code for access token
    # sartu kodea hemen

    print("auth_code: " + auth_code)
    uri = "https://api.dropboxapi.com/oauth2/token"
    goiburuak = {'Host': 'api.dropboxapi.com', 'Content-Type': 'application/x-www-form-urlencoded'}
    datuak = {'code': auth_code, 'client_id': app_key, 'client_secret': app_secret, 'redirect_uri': redirect_uri,
              'grant_type': 'authorization_code'}
    erantzuna = requests.post(uri, headers=goiburuak, data=datuak, allow_redirects=False)
    status = erantzuna.status_code
    edukia = erantzuna.text
    edukia_json = json.loads(edukia)
    access_token = edukia_json['access_token']
    print("Status: ")
    print(str(status))
    print("Edukia: ")
    print(edukia)
    print("access_token: ")
    print(access_token)

    return access_token


def list_folder(access_token, cursor="", edukia_json_entries=[]):
    if not cursor:
        print("/list_folder")
        uri = "https://api.dropboxapi.com/2/files/list_folder"
        datuak = {'path': ''}
    else:
        print("/list_folder/continue")
        uri = "https://api.dropboxapi.com/2/files/list_folder/continue"
        datuak = {"cursor": cursor}

    # Call Dropbox API
    # sartu kodea hemen
    goiburuak = {'Host': 'api.dropboxapi.com',
                 'Authorization': 'Bearer ' + access_token,
                 'Content-Type': 'application/json'}
    datuak_json = json.dumps(datuak)
    erantzuna = requests.post(uri, headers=goiburuak, data=datuak_json, allow_redirects=False)
    status = erantzuna.status_code
    print("\tStatus: " + str(status))
    edukia = erantzuna.text
    print("\tEdukia:")
    print(edukia)

    # See if there are more entries available. Process data.
    edukia_json = json.loads(edukia)
    print("\n\t ########## FITXATEGI ZERRENDA ########## \n")

    for n in edukia_json['entries']:
        izena=n['name']
        print(izena+"\n")
    if edukia_json['has_more']:
        # sartu kodea hemen
        list_folder(access_token,edukia_json['cursor'])

access_token = do_oauth()
list_folder(access_token)
