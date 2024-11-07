from messaging.models import Message, Communication
from messaging.serializers import MessageSerializer, CommunicationSerializer
from rest_framework import generics
from rest_framework.exceptions import PermissionDenied


class MessageList(generics.ListCreateAPIView):
    """
    This class handles listing and creating messages in our REST API.
    - GET: List messages in a specific communication where the user is a participant.
    - POST: Create a new message in a communication, only if the user is a participant.
    """

    serializer_class = MessageSerializer

    def get_queryset(self):
        """
        Filter messages to only show messages in a specific communication where the user is a participant.
        """
        communication_id = self.kwargs.get("communication_id")
        if not communication_id:
            raise PermissionDenied("Communication ID is required to list messages.")

        # Retrieve the communication object
        try:
            communication = Communication.objects.get(id=communication_id)
        except Communication.DoesNotExist:
            raise PermissionDenied("Communication not found.")

        # Check if the user is a participant in the communication
        if not communication.is_participant(self.request.user):
            raise PermissionDenied(
                "You are not allowed to view messages in this communication."
            )

        # If the user is a participant, return the messages in the communication
        return Message.objects.filter(communication=communication)

    def perform_create(self, serializer):
        """
        Ensure the message is created by a participant of the communication.
        """
        communication = serializer.validated_data[
            "communication"
        ]  # Get the related communication

        if not communication.is_participant(self.request.user):
            raise PermissionDenied(
                "You are not allowed to send messages in this communication."
            )

        # Save the message with the current user automatically set in the serializer
        serializer.save(user=self.request.user)


class MessageDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    This class handles operations for a single message instance.
    - GET: Retrieve the details of a specific message (accessible by all participants in the communication).
    - PUT/PATCH: Update the message instance (accessible only by the message author).
    - DELETE: Remove the specific message instance (accessible only by the message author).
    """

    serializer_class = MessageSerializer

    def get_queryset(self):
        """
        Filter messages so that users can only retrieve messages if they are a participant
        in the related communication.
        """
        return Message.objects.filter(
            communication__from_user=self.request.user
        ) | Message.objects.filter(communication__to_user=self.request.user)

    def get_object(self):
        """
        Retrieve the message and ensure the requesting user is a participant in the communication.
        """
        obj = super().get_object()
        if not obj.communication.is_participant(self.request.user):
            raise PermissionDenied("You are not allowed to view this message.")
        return obj

    def perform_update(self, serializer):
        """
        Ensure that only the author of the message can update it.
        """
        message = self.get_object()  # Get the message object
        if message.user != self.request.user:
            raise PermissionDenied("You are not allowed to modify this message.")
        serializer.save()

    def perform_destroy(self, instance):
        """
        Ensure that only the author of the message can delete it.
        """
        if instance.user != self.request.user:
            raise PermissionDenied("You are not allowed to delete this message.")
        instance.delete()


class CommunicationList(generics.ListCreateAPIView):
    """This class handles listing and creating communications in our REST API."""

    serializer_class = CommunicationSerializer

    def get_queryset(self):
        """
        Filter communications to only show those where the user is a participant.
        """
        return Communication.objects.filter(
            from_user=self.request.user
        ) | Communication.objects.filter(to_user=self.request.user)

    def perform_create(self, serializer):
        """
        Ensure the communication is created with the current user as either the sender or receiver.
        """
        from_user = self.request.user  # Current user as sender
        to_user = serializer.validated_data.get("to_user")

        # Ensure the current user is either the sender or receiver
        if from_user == to_user:
            raise PermissionDenied("You cannot communicate with yourself.")

        serializer.save(from_user=from_user)


class CommunicationDetail(generics.RetrieveUpdateDestroyAPIView):
    """This class handles operations for a single communication instance."""

    serializer_class = CommunicationSerializer

    def get_queryset(self):
        """
        Filter communications so that users can only access communications where they are a participant.
        """
        return Communication.objects.filter(
            from_user=self.request.user
        ) | Communication.objects.filter(to_user=self.request.user)

    def get_object(self):
        """
        Retrieve the object, ensuring that the user is a participant in the communication.
        """
        obj = super().get_object()
        if obj.from_user != self.request.user and obj.to_user != self.request.user:
            raise PermissionDenied("You are not allowed to access this communication.")
        return obj

    def perform_update(self, serializer):
        """
        Ensure that only the recipient of the communication can update its status.
        """
        communication = self.get_object()

        # Check if the user is the recipient
        if communication.to_user != self.request.user:
            raise PermissionDenied("You are not allowed to modify this communication.")

        serializer.save()

    def perform_destroy(self, instance):
        """
        Ensure that only participants of the communication can delete it.
        """
        if (
            instance.from_user != self.request.user
            and instance.to_user != self.request.user
        ):
            raise PermissionDenied("You are not allowed to delete this communication.")
        instance.delete()
