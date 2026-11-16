import json
import secrets
import hashlib
import hmac
import os
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



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
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	####/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('insert into Usuario values(null,%s,%s,%s)', (request.json['uname'], request.json['email'], hashPassword(request.json['password'])))
			R = cursor.lastrowid
			db.commit()
		db.close()
	except Exception as e:
		print(e) 
		return {"R":-2}
	return {"R":0,"D":R}




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
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id, password from Usuario where uname = %s', (request.json['uname'],))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	idLogin = R[0][0]
	passwordGuardado = R[0][1]
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
	# R003 - segundo factor: OTP de 6 digitos con vigencia de 5 minutos
	if 'otp' not in request.json:
		codigo = '%06d' % secrets.randbelow(1000000)
		try:
			with db.cursor() as cursor:
				cursor.execute('delete from AccesoToken where id_Usuario = %s', (idLogin,))
				cursor.execute('insert into AccesoToken values(%s,%s,now())', (idLogin, 'OTP:' + codigo))
			db.commit()
			db.close()
		except Exception as e:
			print(e)
			db.close()
			return {"R":-4}
		# En produccion el OTP viaja por correo/SMS; para la demo se devuelve en la respuesta
		return {"R":0,"D":{"otp_required":1,"id_Usuario":idLogin,"otp":codigo}}
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where id_Usuario = %s and token = %s and fecha > (now() - interval 5 minute)', (idLogin, 'OTP:' + str(request.json['otp']).strip()))
			R = cursor.fetchall()
	except Exception as e:
		print(e)
		db.close()
		return {"R":-5}
	if not R:
		db.close()
		return {"R":-5}

	T = getToken();
	
	
	try:
		with db.cursor() as cursor:
			cursor.execute('delete from AccesoToken where id_Usuario = %s', (idLogin,))
			cursor.execute('insert into AccesoToken values(%s,%s,now())', (idLogin, T))
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}

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
	R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)

	# Validar si el usuario esta en la base de datos
	TKN = request.json['token'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s', (TKN,))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-4}
	id_Usuario = R[0][0]
	EXTENSIONES = ('png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'txt', 'pdf')
	ext = request.json['ext']
	ext = str(ext).strip().lower().lstrip('.')
	if ext not in EXTENSIONES:
		db.close()
		return {"R":-5}
	nombre = ''.join(c for c in str(request.json['name']) if c.isalnum() or c in '._ -')[:120]
	if not nombre.strip() or nombre.strip('. ') == '':
		nombre = 'archivo'
	with open(f'tmp/{id_Usuario}',"wb") as imagen:
		imagen.write(base64.b64decode(request.json['data'].encode()))
	
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
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	try:
		idImagen = int(request.json['id'])
	except (TypeError, ValueError):
		db.close()
		return {"R":-1}
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = %s limit 1', (TKN,))
			R = cursor.fetchall()
		if not R:
			db.close()
			return {"R":-2}
		id_UsuarioToken = R[0][0]
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
		
	
	
	# Buscar imagen y enviarla
	
	try:
		with db.cursor() as cursor:
			cursor.execute('select name, ruta, id_Usuario from Imagen where id = %s', (idImagen,))
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	if not R:
		db.close()
		return {"R":-3}
	if str(R[0][2]) != str(id_UsuarioToken):
		db.close()
		return {"R":-4}

	print(Path("img").resolve(),R[0][1])
	return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=False)
