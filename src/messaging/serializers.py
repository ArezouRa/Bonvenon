from rest_framework import serializers
from messaging.models import Message, Communication


class MessageSerializer(serializers.ModelSerializer):
    # Use a PrimaryKeyRelatedField for communication to reference it by ID
    communication = serializers.PrimaryKeyRelatedField(
        queryset=Communication.objects.all()
    )

    class Meta:
        model = Message
        fields = ["id", "communication", "created_at", "msg"]
        read_only_fields = ["created_at"]

    def validate(self, data):
        """Check if communication is accepted before sending a message."""
        communication = data.get("communication")
        if not communication.is_communication_allowed():
            raise serializers.ValidationError(
                "Messages can only be sent in accepted communications."
            )
        return data

    def create(self, validated_data):
        """Custom create method to handle logic for associating the current user."""
        user = self.context["request"].user
        validated_data.pop("user", None)  # Ensure 'user' is not in validated_data
        return Message.objects.create(user=user, **validated_data)


class CommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Communication
        fields = ["id", "to_user", "from_user", "status"]
        read_only_fields = ["from_user"]  # Only 'from_user' is read-only

    def update(self, instance, validated_data):
        """Custom update method to ensure the recipient is the only one who can change the status."""
        request = self.context.get("request")
        if request and request.user != instance.to_user:
            raise serializers.ValidationError(
                "Only the recipient can update the status."
            )

        # Update the status if it's provided
        if "status" in validated_data:
            instance.status = validated_data["status"]

        instance.save()
        return instance
