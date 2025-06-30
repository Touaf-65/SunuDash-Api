from django.db.models.signals import pre_delete, post_save
from django.dispatch import receiver
from .models import File

@receiver(pre_delete, sender=File)
def delete_related_data(sender, instance, **kwargs):

    instance.invoices.all().delete()
    instance.claims.all().delete()
