from rest_framework import serializers
from .models import (
    File, Client, Policy, Insured, InsuredEmployer, Invoice,
    Partner, PaymentMethod, Act, ActFamily, ActCategory,
    Operator, Claim
)

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'user', 'file', 'uploaded_at', 'size', 'file_type', 'country', 'status']
        read_only_fields = ['id', 'user', 'uploaded_at', 'size', 'country']

class ClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = '__all__'

class PolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = Policy
        fields = '__all__'

class InsuredSerializer(serializers.ModelSerializer):
    class Meta:
        model = Insured
        fields = '__all__'

class InsuredEmployerSerializer(serializers.ModelSerializer):
    class Meta:
        model = InsuredEmployer
        fields = '__all__'

class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = '__all__'

class PartnerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Partner
        fields = '__all__'

class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = '__all__'

class ActSerializer(serializers.ModelSerializer):
    class Meta:
        model = Act
        fields = '__all__'

class ActFamilySerializer(serializers.ModelSerializer):
    class Meta:
        model = ActFamily
        fields = '__all__'

class ActCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ActCategory
        fields = '__all__'

class OperatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Operator
        fields = '__all__'

class ClaimSerializer(serializers.ModelSerializer):
    class Meta:
        model = Claim
        fields = '__all__'
