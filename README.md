# Déploiement Caprover

Pour déploiement correctement ce projet sur caprover, il convient de définir les trois variables d'environnement suivantes :
<ul>
  <li> Mot de passe de la base de données :
        
    SANTA_WEBAPP_DB_PASSWORD
  </li>
  <li> Poivre pour sécuriser les mots de passe des utilisateurs : 
    
    SANTA_WEBAPP_USER_PEPPER
  </li>
  <li> Poivre pour sécuriser les mots de passe des groupes :
    
    SANTA_WEBAPP_GROUP_PEPPER
  </li>
</ul>

Pour cela, le script Python ```secret_generator.py``` est disponible à la racine du projet. Pour l'utiliser, il suffit de lancer la commande :
```python3 secret_generator.py```.

Il suffit alors d'aller dans le panneau de configuration de l'application sur l'interface web d'administration de Caprover et de créer les nouvelles entrées correspondantes pour les variables d'environnement.

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
