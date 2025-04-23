import streamlit as st
import paramiko
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time
import os
from io import BytesIO

class NetworkDeviceScanner:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.ssh_timeout = 10
        self.command_timeout = 15
        self.max_workers = 20  # Ajustar según capacidad

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
            st.warning(f"Timeout al conectar a {device_ip}")
            return None
        except Exception as e:
            st.warning(f"Error al conectar a {device_ip} ({device_type}): {str(e)}")
            return None

    def execute_command(self, ssh, command):
        """Ejecuta un comando y devuelve la salida"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=self.command_timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            
            if error and "Invalid input detected" not in error:
                st.warning(f"Error en comando: {error}")
                return None
            return output
        except Exception as e:
            st.warning(f"Error ejecutando comando: {str(e)}")
            return None

    def check_duplicate_ip(self, device_ip, device_type, target_ip):
        """Verifica si la IP está en el dispositivo"""
        ssh = self.connect_to_device(device_ip, device_type)
        if not ssh:
            return device_ip, device_type, None
        
        try:
            # Determinar el comando según el tipo de dispositivo
            if 'huawei' in device_type.lower():
                command = f"display ip routing-table {target_ip}"
            elif 'xe' in device_type.lower():
                command = f"show ip route {target_ip}"
            elif 'xr' in device_type.lower():
                command = f"show route {target_ip}"
            else:
                st.warning(f"Tipo de dispositivo no reconocido: {device_type}")
                return device_ip, device_type, None
            
            output = self.execute_command(ssh, command)
            
            # Analizar la salida
            if output:
                if 'huawei' in device_type.lower():
                    if target_ip in output and "Routing Table" in output:
                        return device_ip, device_type, output
                elif 'xe' in device_type.lower():
                    if target_ip in output and ("Network" in output or "Known" in output or "is directly connected" in output):
                        return device_ip, device_type, output
                elif 'xr' in device_type.lower():
                    if target_ip in output and ("Network" in output or "Known" in output):
                        return device_ip, device_type, output
            
            return device_ip, device_type, None
        except Exception as e:
            st.warning(f"Error procesando {device_ip}: {str(e)}")
            return device_ip, device_type, None
        finally:
            if ssh:
                ssh.close()

    def process_devices(self, excel_data, target_ip, progress_bar, progress_text):
        """Procesa todos los dispositivos en el archivo Excel usando ThreadPool"""
        try:
            df = pd.read_excel(BytesIO(excel_data))
            # Validar que el DataFrame tenga las columnas correctas
            if 'IP' not in df.columns or 'Tipo' not in df.columns:
                st.error("El archivo Excel debe contener columnas 'IP' y 'Tipo'")
                return None
                
            devices = [(str(row['IP']), str(row['Tipo']).lower()) for _, row in df.iterrows()]
        except Exception as e:
            st.error(f"Error al leer el archivo Excel: {str(e)}")
            return None
        
        st.info(f"Iniciando búsqueda de {target_ip} en {len(devices)} dispositivos...")
        
        found_devices = []
        start_time = time.time()
        total_devices = len(devices)
        processed_devices = 0
        
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
                processed_devices += 1
                progress = processed_devices / total_devices
                progress_bar.progress(progress)
                progress_text.text(f"Procesando {processed_devices}/{total_devices} dispositivos...")
                
                try:
                    result_ip, result_type, output = future.result()
                    if output:
                        st.success(f"¡IP ENCONTRADA en {result_ip} ({result_type})!")
                        with st.expander("Ver detalles"):
                            st.text(output)
                        found_devices.append((result_ip, result_type, output))
                except Exception as e:
                    st.warning(f"Error procesando {device_ip}: {str(e)}")
        
        elapsed_time = time.time() - start_time
        st.info(f"Búsqueda completada en {elapsed_time:.2f} segundos")
        
        return found_devices

def main():
    st.title("🔍 Escáner Avanzado de IP en Redes")
    st.markdown("""
    Este script identifica direcciones IP en equipos de red usando conexiones SSH paralelas.
    """)
    
    # Sidebar para credenciales
    with st.sidebar:
        st.header("Credenciales SSH")
        username = st.text_input("Usuario", "juribeb")
        password = st.text_input("Contraseña", type="password")
        st.markdown("---")
        st.info("El archivo Excel debe contener columnas 'IP' y 'Tipo'")
    
    # Carga de archivo
    uploaded_file = st.file_uploader("Sube tu archivo Excel con dispositivos", type=['xlsx'])
    
    if uploaded_file is not None:
        # Input para IP objetivo
        target_ip = st.text_input("IP a buscar", "172.20.142.101")
        
        if st.button("Iniciar Escaneo") and target_ip:
            try:
                # Validar formato de IP
                parts = target_ip.split('.')
                if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                    st.error("Formato de IP inválido")
                    return
                
                # Mostrar progreso
                progress_bar = st.progress(0)
                progress_text = st.empty()
                status_text = st.empty()
                
                # Crear scanner y procesar
                scanner = NetworkDeviceScanner(username, password)
                found_devices = scanner.process_devices(
                    uploaded_file.read(), 
                    target_ip, 
                    progress_bar, 
                    progress_text
                )
                
                # Mostrar resultados finales
                status_text.empty()
                if found_devices:
                    st.success("Resumen de dispositivos con la IP encontrada:")
                    for device_ip, device_type, _ in found_devices:
                        st.write(f"- {device_ip} ({device_type})")
                else:
                    st.warning(f"La IP {target_ip} no se encontró en ningún dispositivo listado")
                
            except Exception as e:
                st.error(f"Error durante el escaneo: {str(e)}")

if __name__ == "__main__":
    main()
