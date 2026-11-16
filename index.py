import json
import secrets
import hashlib
import hmac
import os
import mysql.connector
import base64
import gzip
import shutil
from pathlib import Path
from bottle import run, post, request, static_file



def loadDatabaseSettings(pathjs):
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson
	
"""
function loadDatabaseSettings(pathjs):
	string = file_get_contents(pathjs);
	json_a = json_decode(string, true);
	return json_a;

"""

def conectarBd():
	dbcnf = loadDatabaseSettings('db.json')
	return mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

PBKDF2_ITERACIONES = 260000

def hashPassword(password):
	sal = os.urandom(16)
	dk = hashlib.pbkdf2_hmac('sha256', str(password).encode(), sal, PBKDF2_ITERACIONES)
	return 'pbkdf2_sha256$%d$%s$%s' % (PBKDF2_ITERACIONES, base64.b64encode(sal).decode(), base64.b64encode(dk).decode())

def verifyPassword(password, guardado):
	if not guardado:
		return False
	guardado = str(guardado)
	if guardado.startswith('pbkdf2_sha256$'):
		try:
			_, iteraciones, sal, esperado = guardado.split('$')
			dk = hashlib.pbkdf2_hmac('sha256', str(password).encode(), base64.b64decode(sal), int(iteraciones))
			return hmac.compare_digest(base64.b64encode(dk).decode(), esperado)
		except Exception:
			return False
	return hmac.compare_digest(hashlib.md5(str(password).encode()).hexdigest(), guardado.lower())

def getToken():
	return secrets.token_urlsafe(32)

def guardarToken(db, idUsuario, valor):
	with db.cursor() as cursor:
		cursor.execute('delete from AccesoToken where id_Usuario = %s', (idUsuario,))
		cursor.execute('insert into AccesoToken values(%s,%s,now())', (idUsuario, valor))
	db.commit()

def leerImagen(data):
	try:
		contenido = base64.b64decode(str(data), validate=True)
		if contenido[:2] == b'\x1f\x8b':
			contenido = gzip.decompress(contenido)
		return contenido
	except Exception:
		return None

"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
	db = conectarBd();
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	camposOk = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not camposOk:
		return {"R":-1}
	# TODO validar correo en json
	# TODO Control de error de la DB
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Usuario values(null,%s,%s,%s)', (request.json['uname'], request.json['email'], hashPassword(request.json['password'])))
			idNuevo = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	return {"R":0,"D":idNuevo}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
	db = conectarBd();
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	camposOk = 'uname' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not camposOk:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	try:
		with db.cursor() as cursor:
			cursor.execute('select id, password from Usuario where uname = %s', (request.json['uname'],))
			usuario = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not usuario:
		db.close()
		return {"R":-3}
	
	idLogin = usuario[0][0]
	passwordGuardado = usuario[0][1]
	if not verifyPassword(request.json['password'], passwordGuardado):
		db.close()
		return {"R":-3}
	if not str(passwordGuardado).startswith('pbkdf2_sha256$'):
		try:
			with db.cursor() as cursor:
				cursor.execute('update Usuario set password = %s where id = %s', (hashPassword(request.json['password']), idLogin))
			db.commit()
		except Exception as e:
			print(e)
	if 'otp' not in request.json:
		codigo = '%06d' % secrets.randbelow(1000000)
		try:
			guardarToken(db, idLogin, 'OTP:' + codigo)
		except Exception as e:
			print(e)
			db.close()
			return {"R":-4}
		db.close()
		return {"R":0,"D":{"otp_required":1,"id_Usuario":idLogin,"otp":codigo}}

	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where id_Usuario = %s and token = %s and fecha > (now() - interval 5 minute)', (idLogin, 'OTP:' + str(request.json['otp']).strip()))
			otpValido = cursor.fetchall()
	except Exception as e:
		print(e)
		db.close()
		return {"R":-5}
	if not otpValido:
		db.close()
		return {"R":-5}

	token = getToken()
	try:
		guardarToken(db, idLogin, token)
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}
	db.close()
	return {"R":0,"D":token}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
	#Directorio
	tmp = Path('tmp')
	if not tmp.exists():
		tmp.mkdir()
	img = Path('img')
	if not img.exists():
		img.mkdir()
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	camposOk = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not camposOk:
		return {"R":-1}
	
	db = conectarBd();

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,))
			filaToken = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not filaToken:
		db.close()
		return {"R":-4}
	id_Usuario = filaToken[0][0]
	EXTENSIONES = ('png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'txt', 'pdf')
	ext = request.json['ext']
	ext = str(ext).strip().lower().lstrip('.')
	if ext not in EXTENSIONES:
		db.close()
		return {"R":-5}
	nombre = ''.join(c for c in str(request.json['name']) if c.isalnum() or c in '._ -')[:120]
	if not nombre.strip('. '):
		nombre = 'archivo'
	contenido = leerImagen(request.json['data'])
	if not contenido:
		db.close()
		return {"R":-6}
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(contenido)
	
	############################
	############################
	# Guardar info del archivo en la base de datos
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Imagen values(null,%s,%s,%s)', (nombre, 'img/', id_Usuario))
			idImagen = cursor.lastrowid
			cursor.execute('update Imagen set ruta = %s where id = %s', ('img/' + str(idImagen) + '.' + ext, idImagen))
			db.commit()
			# Mover archivo a su nueva locacion
			shutil.move('tmp/'+str(id_Usuario),'img/'+str(idImagen)+'.'+ext)
			return {"R":0,"D":idImagen}
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Descargar')
def Descargar():
	db = conectarBd();
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	camposOk = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not camposOk:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	try:
		idImagen = int(request.json['id'])
	except (TypeError, ValueError):
		db.close()
		return {"R":-1}
	
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s limit 1', (TKN,))
			filaToken = cursor.fetchall()
		if not filaToken:
			db.close()
			return {"R":-2}
		id_UsuarioToken = filaToken[0][0]
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
		
	
	
	# Buscar imagen y enviarla
	
	try:
		with db.cursor() as cursor:
			cursor.execute('select name, ruta, id_Usuario from Imagen where id = %s', (idImagen,))
			imagen = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	if not imagen:
		db.close()
		return {"R":-3}
	if str(imagen[0][2]) != str(id_UsuarioToken):
		db.close()
		return {"R":-4}

	return static_file(imagen[0][1], Path(".").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=False)
