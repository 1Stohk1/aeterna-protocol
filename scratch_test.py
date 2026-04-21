import sys
sys.path.insert(0, '/mnt/d/Documents/Programmazione/aeterna-protocol/core')
import grpc
import signer_pb2
import signer_pb2_grpc

channel = grpc.insecure_channel('unix:///tmp/test3.sock')
stub = signer_pb2_grpc.SignerStub(channel)
try:
    resp = stub.GetStatus(signer_pb2.GetStatusRequest())
    print("SUCCESS")
except Exception as e:
    print(f"FAILED: {e}")
