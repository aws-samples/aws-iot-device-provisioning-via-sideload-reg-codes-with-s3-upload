FROM public.ecr.aws/amazonlinux/amazonlinux:latest
RUN yum install -y amazon-linux-extras wget
RUN amazon-linux-extras install python3
RUN pip3 install pip --upgrade
RUN wget -O /tmp/AmazonRootCA1.pem https://www.amazontrust.com/repository/AmazonRootCA1.pem
ADD ./requirements.txt /home
WORKDIR /home
RUN pip3 install -r requirements.txt
ADD . /home
EXPOSE 5000
CMD python3 iot_client.py
