"""
IoT Device Integration for InventoryApp

Supports:
- RFID Readers (EPC Gen2, ISO 15693, ISO 14443)
- Barcode Scanners (USB, Bluetooth)
- Environmental Sensors (Temperature, Humidity)
- GPS/Location Trackers
- Smart Locks/Access Control
- Weighing Scales

Protocols:
- MQTT (primary)
- REST API
- WebSockets
- Modbus TCP/RTU
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
import json
import asyncio
import uuid

# MQTT Client
try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False
    print("⚠️ paho-mqtt not available. Install with: pip install paho-mqtt")

# Database (TimescaleDB for time-series data)
from sqlalchemy import create_engine, Column, String, Float, DateTime, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

# ============================================================================
# Models
# ============================================================================

class RFIDRead(Base):
    """RFID tag read event"""
    __tablename__ = 'rfid_reads'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    reader_id = Column(String(100), nullable=False, index=True)
    tag_epc = Column(String(100), nullable=False, index=True)  # Electronic Product Code
    rssi = Column(Float)  # Signal strength
    antenna_id = Column(Integer)
    read_count = Column(Integer, default=1)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    location = Column(String(200))
    metadata = Column(JSON)
    tenant_id = Column(String(36), index=True)

class SensorReading(Base):
    """Environmental sensor reading"""
    __tablename__ = 'sensor_readings'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sensor_id = Column(String(100), nullable=False, index=True)
    sensor_type = Column(String(50))  # temperature, humidity, pressure, etc.
    value = Column(Float, nullable=False)
    unit = Column(String(20))  # °C, %, Pa, etc.
    location = Column(String(200))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    metadata = Column(JSON)
    tenant_id = Column(String(36), index=True)

class DeviceStatus(Base):
    """IoT device status and health"""
    __tablename__ = 'device_status'

    device_id = Column(String(100), primary_key=True)
    device_type = Column(String(50))  # rfid_reader, scanner, sensor, tracker
    status = Column(String(20))  # online, offline, error
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    firmware_version = Column(String(50))
    battery_level = Column(Float)  # Percentage
    ip_address = Column(String(45))
    metadata = Column(JSON)
    tenant_id = Column(String(36), index=True)

# ============================================================================
# Pydantic Schemas
# ============================================================================

class RFIDReadSchema(BaseModel):
    reader_id: str
    tag_epc: str
    rssi: Optional[float] = None
    antenna_id: Optional[int] = None
    location: Optional[str] = None
    metadata: Optional[Dict] = None

class SensorReadingSchema(BaseModel):
    sensor_id: str
    sensor_type: str
    value: float
    unit: str
    location: Optional[str] = None
    metadata: Optional[Dict] = None

class DeviceHeartbeat(BaseModel):
    device_id: str
    device_type: str
    firmware_version: Optional[str] = None
    battery_level: Optional[float] = None
    ip_address: Optional[str] = None
    metadata: Optional[Dict] = None

# ============================================================================
# MQTT Handler
# ============================================================================

class MQTTHandler:
    """
    MQTT client for IoT devices

    Topics:
    - inventory/rfid/{reader_id}/read
    - inventory/sensor/{sensor_id}/reading
    - inventory/device/{device_id}/heartbeat
    - inventory/item/{item_id}/location
    """

    def __init__(self, broker_host='localhost', broker_port=1883):
        if not MQTT_AVAILABLE:
            raise ImportError("paho-mqtt not available")

        self.client = mqtt.Client(client_id=f"inventory-iot-{uuid.uuid4().hex[:8]}")
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.connected = False

        # Callbacks
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect

        # Message handlers
        self.handlers = {}

    def on_connect(self, client, userdata, flags, rc):
        """Called when connected to MQTT broker"""
        if rc == 0:
            self.connected = True
            print(f"✅ Connected to MQTT broker at {self.broker_host}:{self.broker_port}")

            # Subscribe to topics
            self.client.subscribe("inventory/rfid/+/read")
            self.client.subscribe("inventory/sensor/+/reading")
            self.client.subscribe("inventory/device/+/heartbeat")
            self.client.subscribe("inventory/item/+/location")
        else:
            print(f"❌ Failed to connect to MQTT broker: {rc}")

    def on_disconnect(self, client, userdata, rc):
        """Called when disconnected from MQTT broker"""
        self.connected = False
        print(f"⚠️ Disconnected from MQTT broker")

    def on_message(self, client, userdata, msg):
        """Called when a message is received"""
        try:
            topic = msg.topic
            payload = json.loads(msg.payload.decode())

            print(f"📨 MQTT Message: {topic} - {payload}")

            # Route to appropriate handler
            if '/rfid/' in topic:
                self.handle_rfid_read(payload)
            elif '/sensor/' in topic:
                self.handle_sensor_reading(payload)
            elif '/heartbeat' in topic:
                self.handle_device_heartbeat(payload)
            elif '/location' in topic:
                self.handle_item_location(payload)

        except Exception as e:
            print(f"❌ Error processing MQTT message: {e}")

    def handle_rfid_read(self, data: Dict):
        """Handle RFID tag read"""
        # Store in database
        # Update item location
        # Trigger alerts if needed
        print(f"🏷️ RFID Read: {data}")

    def handle_sensor_reading(self, data: Dict):
        """Handle sensor reading"""
        # Store in TimescaleDB
        # Check thresholds
        # Send alerts if out of range
        print(f"📊 Sensor Reading: {data}")

    def handle_device_heartbeat(self, data: Dict):
        """Handle device heartbeat"""
        # Update device status
        # Monitor connectivity
        print(f"💓 Device Heartbeat: {data}")

    def handle_item_location(self, data: Dict):
        """Handle item location update"""
        # Update item GPS coordinates
        # Track movement history
        print(f"📍 Location Update: {data}")

    def connect(self):
        """Connect to MQTT broker"""
        try:
            self.client.connect(self.broker_host, self.broker_port, keepalive=60)
            self.client.loop_start()
        except Exception as e:
            print(f"❌ Failed to connect to MQTT broker: {e}")

    def disconnect(self):
        """Disconnect from MQTT broker"""
        self.client.loop_stop()
        self.client.disconnect()

    def publish(self, topic: str, payload: Dict):
        """Publish message to MQTT topic"""
        if not self.connected:
            raise ConnectionError("Not connected to MQTT broker")

        self.client.publish(topic, json.dumps(payload), qos=1)

# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(title="InventoryApp IoT Service", version="1.0.0")

# MQTT handler instance
mqtt_handler = None

@app.on_event("startup")
async def startup_event():
    """Initialize MQTT connection on startup"""
    global mqtt_handler
    if MQTT_AVAILABLE:
        mqtt_handler = MQTTHandler(broker_host='localhost', broker_port=1883)
        mqtt_handler.connect()

@app.on_event("shutdown")
async def shutdown_event():
    """Disconnect MQTT on shutdown"""
    if mqtt_handler:
        mqtt_handler.disconnect()

# ============================================================================
# REST API Endpoints
# ============================================================================

@app.get("/health")
async def health_check():
    """Service health check"""
    return {
        "status": "healthy",
        "service": "iot-service",
        "mqtt_connected": mqtt_handler.connected if mqtt_handler else False,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/rfid/read")
async def rfid_read(data: RFIDReadSchema):
    """
    Record RFID tag read

    This endpoint can be called by RFID readers that support HTTP POST
    """
    # Store in database
    # Publish to MQTT
    if mqtt_handler:
        mqtt_handler.publish(
            f"inventory/rfid/{data.reader_id}/read",
            data.dict()
        )

    return {"message": "RFID read recorded", "tag_epc": data.tag_epc}

@app.post("/api/sensor/reading")
async def sensor_reading(data: SensorReadingSchema):
    """Record sensor reading"""
    # Store in TimescaleDB
    # Check thresholds
    # Publish to MQTT
    if mqtt_handler:
        mqtt_handler.publish(
            f"inventory/sensor/{data.sensor_id}/reading",
            data.dict()
        )

    return {"message": "Sensor reading recorded"}

@app.post("/api/device/heartbeat")
async def device_heartbeat(data: DeviceHeartbeat):
    """Record device heartbeat"""
    # Update device status
    # Publish to MQTT
    if mqtt_handler:
        mqtt_handler.publish(
            f"inventory/device/{data.device_id}/heartbeat",
            data.dict()
        )

    return {"message": "Heartbeat received", "device_id": data.device_id}

@app.get("/api/rfid/tag/{tag_epc}/history")
async def tag_history(tag_epc: str, limit: int = 100):
    """Get read history for an RFID tag"""
    # Query database
    # Return history
    return {
        "tag_epc": tag_epc,
        "history": []  # Placeholder
    }

@app.get("/api/sensor/{sensor_id}/readings")
async def sensor_readings(sensor_id: str, hours: int = 24):
    """Get sensor readings for the last N hours"""
    # Query TimescaleDB
    # Return time-series data
    return {
        "sensor_id": sensor_id,
        "readings": []  # Placeholder
    }

@app.get("/api/devices")
async def list_devices(device_type: Optional[str] = None):
    """List all IoT devices"""
    # Query database
    return {
        "devices": []  # Placeholder
    }

# ============================================================================
# WebSocket for Real-Time Updates
# ============================================================================

class ConnectionManager:
    """Manage WebSocket connections"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

@app.websocket("/ws/iot")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time IoT updates

    Clients can subscribe to:
    - RFID reads
    - Sensor readings
    - Device status changes
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back (in production, handle subscription management)
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ============================================================================
# RFID Reader Integration Examples
# ============================================================================

class ImpinjReader:
    """
    Integration with Impinj Speedway RFID readers

    Uses LLRP (Low Level Reader Protocol)
    """
    def __init__(self, host: str, port: int = 5084):
        self.host = host
        self.port = port

    async def connect(self):
        """Connect to RFID reader"""
        # Implementation using sllurp library
        pass

    async def start_inventory(self):
        """Start continuous inventory"""
        pass

    async def stop_inventory(self):
        """Stop inventory"""
        pass

class ZebraReader:
    """
    Integration with Zebra FX Series RFID readers

    Uses REST API
    """
    def __init__(self, host: str, api_key: str):
        self.host = host
        self.api_key = api_key
        self.base_url = f"http://{host}/api/v1"

    async def get_inventory(self):
        """Get current inventory from reader"""
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/tags",
                headers={"Authorization": f"Bearer {self.api_key}"}
            )
            return response.json()

# ============================================================================
# Sensor Integration Examples
# ============================================================================

class ModbusSensor:
    """
    Integration with Modbus sensors (Temperature, Humidity, etc.)

    Uses Modbus TCP/RTU protocol
    """
    def __init__(self, host: str, port: int = 502, slave_id: int = 1):
        self.host = host
        self.port = port
        self.slave_id = slave_id

    async def read_temperature(self, register: int = 0) -> float:
        """Read temperature from sensor"""
        # Implementation using pymodbus
        # from pymodbus.client import ModbusTcpClient
        # client = ModbusTcpClient(self.host, port=self.port)
        # result = client.read_holding_registers(register, 1, slave=self.slave_id)
        # return result.registers[0] / 10.0  # Example conversion
        return 25.0  # Placeholder

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
