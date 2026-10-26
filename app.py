import base64
import json
import os

import requests
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "chave-local-grafica-epa-altere-depois")
API_URL = os.getenv("API_URL", "http://127.0.0.1:5003").rstrip("/")
PROXIES_LOCAIS = {"http": None, "https": None}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Entre no sistema para continuar."
login_manager.login_message_category = "warning"


class UsuarioWeb(UserMixin):
    """Representa a pessoa autenticada nesta aplicacao web."""

    def __init__(self, id_usuario, nome):
        self.id = str(id_usuario)
        self.nome = nome


@login_manager.user_loader
def carregar_usuario(id_usuario):
    nome = session.get("nome_usuario", "Funcionário")
    if not session.get("token_jwt"):
        return None
    return UsuarioWeb(id_usuario, nome)


def ler_token(token):
    """Lê as informações públicas do token criado pela API; não valida a assinatura."""
    try:
        parte = token.split(".")[1]
        parte += "=" * (-len(parte) % 4)
        conteudo = base64.urlsafe_b64decode(parte.encode("utf-8"))
        return json.loads(conteudo.decode("utf-8"))
    except (IndexError, ValueError, json.JSONDecodeError):
        return {}


def chamar_api(metodo, caminho, dados=None, parametros=None, arquivos=None):
    """Faz uma requisicao do servidor WEB para a API."""
    cabecalhos = {"Accept": "application/json"}
    token = session.get("token_jwt")
    if token:
        cabecalhos["Authorization"] = f"Bearer {token}"

    return requests.request(
        method=metodo,
        url=f"{API_URL}{caminho}",
        json=dados,
        params=parametros,
        headers=cabecalhos,
        files=arquivos,
        timeout=8,
        proxies=PROXIES_LOCAIS,
    )


def dados_json(resposta):
    try:
        resultado = resposta.json()
        return resultado if isinstance(resultado, (dict, list)) else {}
    except ValueError:
        return {}


def mensagem_erro(resposta, mensagem_padrao="Não foi possível concluir a operação."):
    dados = dados_json(resposta)
    if isinstance(dados, dict):
        return dados.get("msg") or dados.get("erro") or dados.get("error") or dados.get("mensagem") or mensagem_padrao
    return mensagem_padrao


def sessao_expirada():
    logout_user()
    session.clear()
    flash("Sua sessão expirou. Entre novamente.", "warning")
    return redirect(url_for("login"))


def inteiro_ou_none(valor):
    try:
        return int(valor) if valor not in (None, "") else None
    except (TypeError, ValueError):
        return None


def listar_equipes_api():
    """Busca as equipes para preencher listas suspensas dos formulários."""
    try:
        resposta = chamar_api("GET", "/equipe/listar")
        if resposta.status_code == 200:
            return dados_json(resposta).get("lista_equipe", [])
    except requests.RequestException:
        pass
    return []


def listar_funcionarios_api():
    try:
        resposta = chamar_api("GET", "/usuarios/listar")
        if resposta.status_code == 200 and isinstance(dados_json(resposta), list):
            return dados_json(resposta)
    except requests.RequestException:
        pass
    return []


# =========================================================
# INICIO E AUTENTICACAO
# =========================================================

@app.route("/")
def inicio():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        senha = request.form.get("senha") or ""

        if not email or not senha:
            flash("Informe o e-mail e a senha.", "danger")
            return render_template("login.html")

        try:
            resposta = chamar_api("POST", "/usuarios/login", dados={"email": email, "senha": senha})
            dados = dados_json(resposta)

            if resposta.status_code == 200 and dados.get("access_token"):
                token = dados["access_token"]
                informacoes = ler_token(token)
                id_usuario = informacoes.get("id_funcinario") or informacoes.get("sub") or email
                nome_usuario = informacoes.get("nome") or email.split("@")[0]

                session.clear()
                session["token_jwt"] = token
                session["nome_usuario"] = nome_usuario
                session["id_usuario"] = str(id_usuario)
                login_user(UsuarioWeb(id_usuario, nome_usuario))
                flash(f"Bem-vindo(a), {nome_usuario}!", "success")
                return redirect(url_for("dashboard"))

            flash(mensagem_erro(resposta, "E-mail ou senha inválidos."), "danger")

        except requests.RequestException:
            flash("Não foi possível conectar à API. Confira se ela está ligada na porta 5003.", "danger")

    return render_template("login.html")


@app.route("/cadastro", methods=["GET", "POST"])
@app.route("/usuarios", methods=["GET", "POST"])
def cadastro():
    if request.method == "GET":
        return render_template("cadastro.html")

    nome = (request.form.get("nome") or "").strip()
    email = (request.form.get("email") or "").strip()
    cpf = "".join(caractere for caractere in (request.form.get("cpf") or "") if caractere.isdigit())
    senha = request.form.get("senha") or ""
    confirmar_senha = request.form.get("confirmar_senha") or ""

    if not all((nome, email, cpf, senha)):
        flash("Preencha nome, CPF, e-mail e senha.", "danger")
        return render_template("cadastro.html")

    if len(cpf) != 11:
        flash("O CPF deve conter 11 números.", "danger")
        return render_template("cadastro.html")

    if senha != confirmar_senha:
        flash("A senha e a confirmação estão diferentes.", "danger")
        return render_template("cadastro.html")

    try:
        resposta = chamar_api(
            "POST",
            "/usuarios/cadastro",
            dados={"nome": nome, "email": email, "cpf": cpf, "senha": senha},
        )

        if resposta.status_code == 201:
            flash("Cadastro realizado! Agora entre com seu e-mail e sua senha.", "success")
            return redirect(url_for("login"))

        flash(mensagem_erro(resposta, "Não foi possível realizar o cadastro."), "danger")

    except requests.RequestException:
        flash("Não foi possível conectar à API. Confira se ela está ligada na porta 5003.", "danger")

    return render_template("cadastro.html")


@app.route("/sair")
@login_required
def sair():
    logout_user()
    session.clear()
    flash("Você saiu do sistema.", "info")
    return redirect(url_for("login"))


# =========================================================
# PAINEL / DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():
    try:
        resposta = chamar_api("GET", "/dashboard/indicadores")
        if resposta.status_code == 401:
            return sessao_expirada()
        if resposta.status_code == 200:
            indicadores = dados_json(resposta).get("indicadores", {})
            return render_template("dashboard.html", indicadores=indicadores)
        flash(mensagem_erro(resposta, "Não foi possível carregar o painel."), "warning")
    except requests.RequestException:
        flash("A API está indisponível. O painel não conseguiu carregar os indicadores.", "danger")

    return render_template("dashboard.html", indicadores={})


# =========================================================
# FUNCIONARIOS
# =========================================================

@app.route("/funcionarios")
@login_required
def funcionarios():
    try:
        resposta = chamar_api("GET", "/usuarios/listar")
        if resposta.status_code == 401:
            return sessao_expirada()
        if resposta.status_code == 200:
            lista = dados_json(resposta)
            if isinstance(lista, list):
                return render_template("funcionarios.html", funcionarios=lista)
        flash(mensagem_erro(resposta, "Não foi possível carregar os funcionários."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return render_template("funcionarios.html", funcionarios=[])


# =========================================================
# EQUIPES E MEMBROS
# =========================================================

@app.route("/equipes")
@app.route("/equipe")
@login_required
def equipes():
    pagina = request.args.get("page", 1, type=int)
    try:
        resposta = chamar_api("GET", "/equipe/listar", parametros={"page": max(1, pagina)})
        if resposta.status_code == 200:
            dados = dados_json(resposta)
            return render_template(
                "equipes.html",
                equipes=dados.get("lista_equipe", []),
                pagina=dados.get("current_page", 1),
                total_paginas=max(1, dados.get("total_pages", 1)),
                total=dados.get("total_equipe", 0),
            )
        flash(mensagem_erro(resposta, "Não foi possível listar as equipes."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API para carregar as equipes.", "danger")
    return render_template("equipes.html", equipes=[], pagina=1, total_paginas=1, total=0)


@app.route("/equipes/nova", methods=["GET", "POST"])
@login_required
def nova_equipe():
    if request.method == "POST":
        cpf = "".join(caractere for caractere in (request.form.get("cpf") or "") if caractere.isdigit())
        nome_equipe = (request.form.get("nome_equipe") or "").strip()

        if not cpf or not nome_equipe:
            flash("Informe o CPF do responsável e o nome da equipe.", "danger")
            return render_template("equipe_form.html")

        try:
            resposta = chamar_api("POST", "/equipe/cadastrar", dados={"cpf": cpf, "nome_equipe": nome_equipe})
            if resposta.status_code == 201:
                flash("Equipe cadastrada com sucesso!", "success")
                return redirect(url_for("equipes"))
            flash(mensagem_erro(resposta, "Não foi possível cadastrar a equipe."), "danger")
        except requests.RequestException:
            flash("Não foi possível conectar à API.", "danger")

    return render_template("equipe_form.html")


@app.route("/equipes/<int:id_equipe>")
@login_required
def detalhe_equipe(id_equipe):
    try:
        resposta = chamar_api("GET", f"/api/equipe/{id_equipe}")
        if resposta.status_code == 200:
            return render_template("equipe_detalhe.html", equipe=dados_json(resposta))
        flash(mensagem_erro(resposta, "Equipe não encontrada."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return redirect(url_for("equipes"))


@app.route("/equipes/<int:id_equipe>/membros/adicionar", methods=["POST"])
@login_required
def adicionar_membro(id_equipe):
    cpf = "".join(caractere for caractere in (request.form.get("cpf") or "") if caractere.isdigit())
    try:
        resposta = chamar_api("POST", f"/equipe/{id_equipe}/membros", dados={"cpf": cpf})
        if resposta.status_code == 201:
            flash(mensagem_erro(resposta, "Funcionário adicionado à equipe."), "success")
        else:
            flash(mensagem_erro(resposta, "Não foi possível adicionar o funcionário."), "danger")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return redirect(url_for("detalhe_equipe", id_equipe=id_equipe))


@app.route("/equipes/<int:id_equipe>/membros/trocar", methods=["POST"])
@login_required
def trocar_membro(id_equipe):
    cpf_antigo = "".join(c for c in (request.form.get("cpf_antigo") or "") if c.isdigit())
    cpf_novo = "".join(c for c in (request.form.get("cpf_novo") or "") if c.isdigit())
    try:
        resposta = chamar_api(
            "PUT",
            f"/equipe/{id_equipe}/membros",
            dados={"cpf_antigo": cpf_antigo, "cpf_novo": cpf_novo},
        )
        if resposta.status_code == 200:
            flash(mensagem_erro(resposta, "Membro substituído com sucesso."), "success")
        else:
            flash(mensagem_erro(resposta, "Não foi possível substituir o membro."), "danger")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return redirect(url_for("detalhe_equipe", id_equipe=id_equipe))


@app.route("/equipes/<int:id_equipe>/membros/<int:id_funcionario>/remover", methods=["POST"])
@login_required
def remover_membro(id_equipe, id_funcionario):
    try:
        resposta = chamar_api("DELETE", f"/equipe/{id_equipe}/membros/{id_funcionario}")
        if resposta.status_code == 200:
            flash("Membro removido da equipe.", "success")
        else:
            flash(mensagem_erro(resposta, "Não foi possível remover o membro."), "danger")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return redirect(url_for("detalhe_equipe", id_equipe=id_equipe))


# =========================================================
# PRODUTOS
# =========================================================

@app.route("/produtos")
@login_required
def produtos():
    pagina = request.args.get("page", 1, type=int)
    try:
        resposta = chamar_api("GET", "/produto/listar", parametros={"page": max(1, pagina)})
        if resposta.status_code == 401:
            return sessao_expirada()
        if resposta.status_code == 200:
            dados = dados_json(resposta)
            return render_template(
                "produtos.html",
                produtos=dados.get("produtos", []),
                pagina=dados.get("current_page", 1),
                total_paginas=max(1, dados.get("total_pages", 1)),
                total=dados.get("total_items", 0),
            )
        flash(mensagem_erro(resposta, "Não foi possível listar os produtos."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return render_template("produtos.html", produtos=[], pagina=1, total_paginas=1, total=0)


@app.route("/produtos/novo", methods=["GET", "POST"])
@login_required
def novo_produto():
    if request.method == "POST":
        descricao = (request.form.get("descricao") or "").strip()
        quantidade = (request.form.get("quantidade_planejada") or "").strip()
        formato = (request.form.get("formato") or "").strip()
        material_id = inteiro_ou_none(request.form.get("material_id"))

        if not all((descricao, quantidade, formato)):
            flash("Preencha descrição, quantidade planejada e formato.", "danger")
            return render_template("produto_form.html", materiais=[])

        dados = {"descricao": descricao, "quantidade_planejada": quantidade, "formato": formato}
        if material_id:
            dados["material_id"] = material_id
        try:
            resposta = chamar_api("POST", "/produto/cadastrar", dados=dados)
            if resposta.status_code == 201:
                flash("Produto cadastrado com sucesso!", "success")
                return redirect(url_for("produtos"))
            flash(mensagem_erro(resposta, "Não foi possível cadastrar o produto."), "danger")
        except requests.RequestException:
            flash("Não foi possível conectar à API.", "danger")

    materiais = []
    try:
        resposta_materiais = chamar_api("GET", "/material/listar")
        if resposta_materiais.status_code == 200:
            materiais = dados_json(resposta_materiais).get("materiais", [])
    except requests.RequestException:
        pass
    return render_template("produto_form.html", materiais=materiais)


@app.route("/produtos/<int:id_produto>/arquivo", methods=["POST"])
@login_required
def enviar_arquivo_produto(id_produto):
    arquivo = request.files.get("arquivo")
    if not arquivo or not arquivo.filename:
        flash("Escolha um arquivo PDF, PNG ou JPG.", "warning")
        return redirect(url_for("produtos"))

    try:
        resposta = chamar_api(
            "POST",
            f"/produto/{id_produto}/upload",
            arquivos={"arquivo": (arquivo.filename, arquivo.stream, arquivo.mimetype)},
        )
        if resposta.status_code == 200:
            flash("Arquivo enviado com sucesso!", "success")
        else:
            flash(mensagem_erro(resposta, "Não foi possível enviar o arquivo."), "danger")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return redirect(url_for("produtos"))


# =========================================================
# MATERIAIS
# =========================================================

@app.route("/materiais")
@login_required
def materiais():
    pagina = request.args.get("page", 1, type=int)
    try:
        resposta = chamar_api("GET", "/material/listar", parametros={"page": max(1, pagina)})
        if resposta.status_code == 401:
            return sessao_expirada()
        if resposta.status_code == 200:
            dados = dados_json(resposta)
            return render_template(
                "materiais.html",
                materiais=dados.get("materiais", []),
                pagina=dados.get("current_page", 1),
                total_paginas=max(1, dados.get("total_pages", 1)),
                total=dados.get("total_items", 0),
            )
        flash(mensagem_erro(resposta, "Não foi possível listar os materiais."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return render_template("materiais.html", materiais=[], pagina=1, total_paginas=1, total=0)


@app.route("/materiais/novo", methods=["GET", "POST"])
@login_required
def novo_material():
    produtos_disponiveis = []
    try:
        resposta_produtos = chamar_api("GET", "/produto/listar")
        if resposta_produtos.status_code == 200:
            produtos_disponiveis = dados_json(resposta_produtos).get("produtos", [])
    except requests.RequestException:
        pass

    if request.method == "POST":
        descricao = (request.form.get("descricao_material") or "").strip()
        unidade = (request.form.get("unidade_medida") or "").strip()
        produto_id = inteiro_ou_none(request.form.get("fk_id_produto"))

        if not descricao or not unidade:
            flash("Preencha a descrição e a unidade de medida.", "danger")
            return render_template("material_form.html", produtos=produtos_disponiveis)

        dados = {"descricao_material": descricao, "unidade_medida": unidade}
        if produto_id:
            dados["fk_id_produto"] = produto_id
        try:
            resposta = chamar_api("POST", "/material/cadastrar", dados=dados)
            if resposta.status_code == 201:
                flash("Material cadastrado com sucesso!", "success")
                return redirect(url_for("materiais"))
            flash(mensagem_erro(resposta, "Não foi possível cadastrar o material."), "danger")
        except requests.RequestException:
            flash("Não foi possível conectar à API.", "danger")

    return render_template("material_form.html", produtos=produtos_disponiveis)


# =========================================================
# PRODUCAO
# =========================================================

@app.route("/producao")
@login_required
def producao():
    pagina = request.args.get("page", 1, type=int)
    data_filtro = request.args.get("data_producao", "").strip()
    funcionario_filtro = request.args.get("fk_id_funcinario", "").strip()
    parametros = {"page": max(1, pagina)}
    if data_filtro:
        parametros["data_producao"] = data_filtro
    if funcionario_filtro:
        parametros["fk_id_funcinario"] = funcionario_filtro

    try:
        resposta = chamar_api("GET", "/producao/listar", parametros=parametros)
        if resposta.status_code == 401:
            return sessao_expirada()
        if resposta.status_code == 200:
            dados = dados_json(resposta)
            return render_template(
                "producao.html",
                producoes=dados.get("producao", []),
                pagina=dados.get("current_page", 1),
                total_paginas=max(1, dados.get("total_pages", 1)),
                total=dados.get("total_items", 0),
                data_filtro=data_filtro,
                funcionario_filtro=funcionario_filtro,
            )
        flash(mensagem_erro(resposta, "Não foi possível listar a produção."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return render_template(
        "producao.html", producoes=[], pagina=1, total_paginas=1, total=0,
        data_filtro=data_filtro, funcionario_filtro=funcionario_filtro,
    )


@app.route("/producao/nova", methods=["GET", "POST"])
@login_required
def nova_producao():
    equipes_disponiveis = listar_equipes_api()
    funcionarios_disponiveis = listar_funcionarios_api()

    if request.method == "POST":
        dados = {
            "fk_id_funcinario": inteiro_ou_none(request.form.get("fk_id_funcinario")),
            "fk_id_equipe": inteiro_ou_none(request.form.get("fk_id_equipe")),
            "hora_inicio_rodagem": request.form.get("hora_inicio_rodagem", "").strip(),
            "hora_fim_rodagem": request.form.get("hora_fim_rodagem", "").strip(),
            "material_perda": request.form.get("material_perda", "").strip(),
            "quantidade_produto": request.form.get("quantidade_produto", "").strip(),
        }

        if not all((dados["hora_inicio_rodagem"], dados["hora_fim_rodagem"], dados["material_perda"], dados["quantidade_produto"])):
            flash("Preencha os horários, a perda de material e a quantidade produzida.", "danger")
            return render_template("producao_form.html", equipes=equipes_disponiveis, funcionarios=funcionarios_disponiveis)

        try:
            resposta = chamar_api("POST", "/producao/cadastrar", dados=dados)
            if resposta.status_code == 201:
                flash("Produção cadastrada com sucesso!", "success")
                return redirect(url_for("producao"))
            if resposta.status_code == 401:
                return sessao_expirada()
            flash(mensagem_erro(resposta, "Não foi possível cadastrar a produção."), "danger")
        except requests.RequestException:
            flash("Não foi possível conectar à API.", "danger")

    return render_template("producao_form.html", equipes=equipes_disponiveis, funcionarios=funcionarios_disponiveis)


# =========================================================
# TURNOS
# =========================================================

@app.route("/turnos")
@login_required
def turnos():
    pagina = request.args.get("page", 1, type=int)
    try:
        resposta = chamar_api("GET", "/turno", parametros={"page": max(1, pagina)})
        if resposta.status_code == 401:
            return sessao_expirada()
        if resposta.status_code == 200:
            dados = dados_json(resposta)
            return render_template(
                "turnos.html",
                turnos=dados.get("turnos", []),
                pagina=dados.get("current_page", 1),
                total_paginas=max(1, dados.get("total_pages", 1)),
                total=dados.get("total_items", 0),
            )
        flash(mensagem_erro(resposta, "Não foi possível listar os turnos."), "warning")
    except requests.RequestException:
        flash("Não foi possível conectar à API.", "danger")
    return render_template("turnos.html", turnos=[], pagina=1, total_paginas=1, total=0)


@app.route("/turnos/novo", methods=["GET", "POST"])
@login_required
def novo_turno():
    equipes_disponiveis = listar_equipes_api()

    if request.method == "POST":
        id_equipe = inteiro_ou_none(request.form.get("fk_id_equipe"))
        nome_equipe = (request.form.get("nome_equipe") or "").strip()
        hora_inicio = (request.form.get("hora_inicio") or "").strip()
        hora_fim = (request.form.get("hora_fim") or "").strip()

        if not all((nome_equipe, hora_inicio, hora_fim)):
            flash("Preencha nome da equipe, horário inicial e horário final.", "danger")
            return render_template("turno_form.html", equipes=equipes_disponiveis)

        dados = {
            "fk_id_equipe": id_equipe,
            "nome_equipe": nome_equipe,
            "hora_inicio": hora_inicio,
            "hora_fim": hora_fim,
        }
        try:
            resposta = chamar_api("POST", "/turno", dados=dados)
            if resposta.status_code == 201:
                flash("Turno cadastrado com sucesso!", "success")
                return redirect(url_for("turnos"))
            if resposta.status_code == 401:
                return sessao_expirada()
            flash(mensagem_erro(resposta, "Não foi possível cadastrar o turno."), "danger")
        except requests.RequestException:
            flash("Não foi possível conectar à API.", "danger")

    return render_template("turno_form.html", equipes=equipes_disponiveis)


if __name__ == "__main__":
    app.run(debug=True, port=5002, host="127.0.0.1")
