FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum install -y amazon-linux-extras wget
RUN amazon-linux-extras install python3
RUN pip3 install pip --upgrade
RUN wget -O /home/AmazonRootCA1.pem https://www.amazontrust.com/repository/AmazonRootCA1.pem
ADD ./requirements.txt /home
RUN pip3 install -r /home/requirements.txt
ADD . /home
EXPOSE 5000
WORKDIR /home
CMD python3 iot_client.py
