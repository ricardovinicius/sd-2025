from concurrent import futures
import grpc
import images_pb2
import images_pb2_grpc

fake_image_db = {
    "1": {"id": "1", "url": "http://example.com/image1.jpg", "description": "Image 1"},
    "2": {"id": "2", "url": "http://example.com/image2.jpg", "description": "Image 2"},
}


class ImagesServicer(images_pb2_grpc.ImagesServiceServicer):
    def GetImages(self, request, context):
        return images_pb2.ImagesList(
            images=[images_pb2.Image(**img) for img in fake_image_db.values()]
        )


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    images_pb2_grpc.add_ImagesServiceServicer_to_server(ImagesServicer(), server)
    server.add_insecure_port("[::]:50052")
    print("Images gRPC ouvindo em 50052")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
