from django.db import models
from users.models import CustomUser as User, Country

class File(models.Model):
    FILE_TYPE_CHOICES = [
        ('stat', 'Fichier Statistique'),
        ('recap', 'Fichier Récap'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    file_type = models.CharField(max_length=5, choices=FILE_TYPE_CHOICES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    size = models.PositiveIntegerField()

    def save(self, *args, **kwargs):
        self.size = self.file.size
        super().save(*args, **kwargs)

    def __str__(self):
        return self.file.name
    



class Client(models.Model):
    id = models.AutoField(primary_key=True)
    contact = models.CharField(max_length=255, null=True, blank=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    name = models.CharField(max_length=255)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, related_name='clients')

    def __str__(self):
        return self.name


class Insured(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    birth_date = models.DateField(null=True, blank=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    card_number = models.CharField(max_length=255, null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    email = models.EmailField(max_length=255, null=True, blank=True)
    consumption_limit = models.FloatField(null=True, blank=True)
    is_primary_insured = models.BooleanField(default=False)
    is_child = models.BooleanField(default=False)
    is_spouse = models.BooleanField(default=False)
    policy = models.ForeignKey('Policy', on_delete=models.CASCADE, related_name='insureds')
    college = models.ForeignKey('College', on_delete=models.CASCADE, related_name='insureds')

    def __str__(self):
        return f'{self.first_name} {self.last_name}'


class College(models.Model):
    id = models.AutoField(primary_key=True)
    label = models.CharField(max_length=255)
    registration_date = models.DateTimeField(auto_now_add=True)
    policy = models.ForeignKey('Policy', on_delete=models.CASCADE, related_name='colleges')

    def __str__(self):
        return self.label


class Policy(models.Model):
    id = models.AutoField(primary_key=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    policy_number = models.CharField(max_length=255)
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='policies')

    def __str__(self):
        return self.policy_number


class Invoice(models.Model):
    id = models.AutoField(primary_key=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    invoice_number = models.CharField(max_length=255)
    claimed_amount = models.FloatField()
    reimbursed_amount = models.FloatField()
    provider = models.ForeignKey('Partner', on_delete=models.CASCADE, related_name='invoices')
    insured = models.ForeignKey(Insured, on_delete=models.CASCADE, related_name='invoices')

    def __str__(self):
        return self.invoice_number


class Partner(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    contact = models.CharField(max_length=255, null=True, blank=True)
    modification_date = models.DateTimeField(auto_now=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    main_responsible_name = models.CharField(max_length=255, null=True, blank=True)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, related_name='partners')

    def __str__(self):
        return self.name


class PaymentMethod(models.Model):
    class TypeEnum(models.TextChoices):
        CASH = 'C', 'Cash'
        CARD = 'D', 'Card'
        BANK_TRANSFER = 'B', 'Bank Transfer'

    class TypePaymentEnum(models.TextChoices):
        CREDIT = 'C', 'Credit'
        DEBIT = 'D', 'Debit'

    id = models.AutoField(primary_key=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    payment_type = models.CharField(max_length=1, choices=TypeEnum.choices)
    payment_number = models.IntegerField()
    payment_method_type = models.CharField(max_length=1, choices=TypePaymentEnum.choices)
    emission_date = models.DateTimeField()
    provider = models.ForeignKey(Partner, on_delete=models.CASCADE, related_name='payment_methods')

    def __str__(self):
        return f'Method {self.payment_number} - {self.payment_method_type}'


class Act(models.Model):
    id = models.AutoField(primary_key=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    label = models.CharField(max_length=255)
    family = models.ForeignKey('ActFamily', on_delete=models.CASCADE, related_name='acts')

    def __str__(self):
        return self.label


class ActFamily(models.Model):
    id = models.AutoField(primary_key=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    label = models.CharField(max_length=255)
    category = models.ForeignKey('ActCategory', on_delete=models.CASCADE, related_name='families')

    def __str__(self):
        return self.label


class ActCategory(models.Model):
    id = models.AutoField(primary_key=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)
    label = models.CharField(max_length=255)

    def __str__(self):
        return self.label


class Claim(models.Model):
    id = models.AutoField(primary_key=True)
    claim_date = models.DateTimeField()
    settlement_date = models.DateTimeField()

    def __str__(self):
        return f'Claim {self.id}'


class Operator(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name
