import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
import tkinter as tk
from tkinter import simpledialog, messagebox

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 10
        self.command_timeout = 15
        self.max_workers = 20  # Ajustar según capacidad de tu estación de trabajo

    def connect_to_device(self, device_ip, device_type):
        """Establece conexión SSH con el dispositivo"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(device_ip, 
                       username=self.username, 
                       password=self.password, 
                       timeout=self.ssh_timeout,
                       banner_timeout=20)
            return ssh
        except socket.timeout:
            print(f"Timeout al conectar a {device_ip}")
            return None
        except Exception as e:
            print(f"Error al conectar a {device_ip}: {str(e)}")
            return None

    def execute_command(self, ssh, command):
        """Ejecuta un comando y devuelve la salida"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            if error:
                print(f"Error en comando: {error}")
                return None
            return output
        except Exception as e:
            print(f"Error ejecutando comando: {str(e)}")
            return None

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Verifica si la IP está en el dispositivo"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return None, None
        
        try:
            # Determinar el comando según el tipo de dispositivo
            if 'huawei' in device_type.lower():
                command = f"dis ip routing-table {target_ip}"
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip}"
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip}"
            else:
                print(f"Tipo de dispositivo no reconocido: {device_type}")
                return device_ip, None
            
            output = self.execute_command(ssh, command)
            
            # Analizar la salida
            if output:
                if 'huawei' in device_type.lower():
                    if target_ip in output and "Routing Table" in output:
                        return device_ip, output
                elif 'xe' in device_type.lower():
                    if target_ip in output and ("Network" in output or "Known" in output):
                        return device_ip, output
                elif 'xr' in device_type.lower():
                    if target_ip in output and ("Network" in output or "Known" in output):
                        return device_ip, output
            
            return device_ip, None
        finally:
            ssh.close()

    def process_devices(self, excel_file, target_ip):
        """Procesa todos los dispositivos en el archivo Excel usando ThreadPool"""
        try:
            df = pd.read_excel(excel_file)
            devices = [(str(row[0]), str(row[1]).lower()) for _, row in df.iterrows()]
        except Exception as e:
            print(f"Error al leer el archivo Excel: {str(e)}")
            return None
        
        print(f"\nIniciando búsqueda de {target_ip} en {len(devices)} dispositivos...")
        
        found_devices = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(
                    self.check_duplicate_ip, 
                    device_ip, 
                    device_type, 
                    target_ip
                ): (device_ip, device_type) 
                for device_ip, device_type in devices
            }
            
            for future in as_completed(futures):
                device_ip, device_type = futures[future]
                try:
                    result_ip, output = future.result()
                    if output:
                        print(f"\n¡IP DUPLICADA ENCONTRADA en {result_ip} ({device_type})!")
                        print(output)
                        found_devices.append((result_ip, device_type, output))
                except Exception as e:
                    print(f"Error procesando {device_ip}: {str(e)}")
        
        elapsed_time = time.time() - start_time
        print(f"\nBúsqueda completada en {elapsed_time:.2f} segundos")
        
        return found_devices

def main():
    print("Script avanzado para identificar IP duplicada en equipos de red")
    print("Usando ThreadPool para ejecución paralela\n")
    
    # Solicitar credenciales
    username = ""
    password = ""
    
    # Crear scanner
    scanner = NetworkDeviceScanner(username, password)
    
    # Solicitar archivo Excel y IP a buscar
    excel_file = "equipos.xlsx"
    target_ip = "172.20.142.101"
    
    # Procesar dispositivos
    found_devices = scanner.process_devices(excel_file, target_ip)

    
    # Mostrar resultados
    if found_devices:
        print("\nResumen de dispositivos con la IP duplicada:")
        for device_ip, device_type, _ in found_devices:
            print(f"- {device_ip} ({device_type})")
    else:
        print(f"\nLa IP {target_ip} no se encontró en ningún dispositivo listado")

if __name__ == "__main__":
    main()
