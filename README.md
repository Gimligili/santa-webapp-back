# Run mariadb
```sh
sudo docker run --name mariadbtest -e MYSQL_ROOT_PASSWORD=mypass -p 3306:3306 -d docker.io/library/mariadb:latest
```
(Mettez le password que vous voulez pour le root password)

Ensuite :
``` sh
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mariadbtest
```
Pour avoir l'IP sur laquelle tourne la DB
Puis dans `config.json` remplacer le host par l'IP ainsi trouvé


# Run back hors docker

Installer les requirements :
(Des problèmes peuvent être rencontrés pour installer `mariadb`)

```sh
pip install -r requirements.txt
```

Lancer backend.py

# Run dans docker

```sh
sudo docker build -t backend-santa:v<version-number> .
sudo docker run --name santawebback -p 5000:5000 backend-santa:v<version-number>
sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' santawebback
```

Pour avoir l'IP sur laquelle faire les appels pour les tests.
Quand on montera le docker compose, sera hardcodé
